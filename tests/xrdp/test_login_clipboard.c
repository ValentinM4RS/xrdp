/* Licensed under the Apache License, Version 2.0. See COPYING. */
#if defined(HAVE_CONFIG_H)
#include <config_ac.h>
#endif
#include "test_xrdp.h"
#include "xrdp.h"
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <limits.h>
#include <stdlib.h>
#if defined(__SANITIZE_ADDRESS__)
#include <sanitizer/asan_interface.h>
#endif

void __real_OPENSSL_cleanse(void *, size_t);
void __wrap_OPENSSL_cleanse(void *, size_t);
static unsigned long long cleansed_bytes;

void
__wrap_OPENSSL_cleanse(void *pointer, size_t bytes)
{
    cleansed_bytes += bytes;
#if defined(__SANITIZE_ADDRESS__)
    /* libcrypto may implement cleanse in uninstrumented assembler. Check its
     * full write range as well as instrumenting the surrounding project code. */
    ck_assert_msg(__asan_region_is_poisoned(pointer, bytes) == NULL,
                  "OPENSSL_cleanse write exceeds the allocation");
#endif
    __real_OPENSSL_cleanse(pointer, bytes);
}

static int test_send(struct xrdp_session *, int, char *, int, int, int);
static int test_channel(struct xrdp_session *, const char *);
static int test_forward(struct xrdp_mm *, tbus, tbus, tbus, tbus);
static int test_invalidate(struct xrdp_bitmap *, struct xrdp_rect *);
static int fail_allocation;

static void *
test_calloc(size_t count, size_t bytes)
{
    return fail_allocation ? NULL : calloc(count, bytes);
}

/* Exercise the real parser and UI glue with only its transport/drawing edges
 * replaced. The normal WM -> chansrv route is tested with a real socket below. */
#define libxrdp_send_to_channel test_send
#define libxrdp_get_channel_id test_channel
#define xrdp_mm_process_channel_data test_forward
#define xrdp_bitmap_invalidate test_invalidate
#define calloc test_calloc
#include "../../xrdp/xrdp_login_clipboard.c"
#undef calloc
#undef libxrdp_send_to_channel
#undef libxrdp_get_channel_id
#undef xrdp_mm_process_channel_data
#undef xrdp_bitmap_invalidate

struct clip_fixture
{
    struct xrdp_wm wm;
    struct xrdp_config config;
    struct xrdp_client_info client;
    struct xrdp_session session;
    struct xrdp_mm mm;
    struct xrdp_mod mod;
    struct xrdp_process process;
    struct xrdp_bitmap window;
    struct xrdp_bitmap edit;
    char caption[256];
};

static unsigned char sent[32];
static unsigned char forwarded[LOGIN_CLIP_MAX_PDU];
static int sent_size;
static int send_count;
static int forwarded_size;
static int forward_count;
static int invalidations;
static int available_channel;

static int
test_send(struct xrdp_session *s, int channel, char *data, int bytes, int total, int flags)
{
    (void)s;
    ck_assert_int_eq(channel, 7);
    ck_assert_int_eq(bytes, total);
    ck_assert_int_eq(flags, XR_CHANNEL_FLAG_FIRST | XR_CHANNEL_FLAG_LAST);
    ck_assert_int_le(bytes, sizeof(sent));
    memcpy(sent, data, bytes);
    sent_size = bytes;
    ++send_count;
    return 0;
}

static int
test_channel(struct xrdp_session *s, const char *name)
{
    (void)s;
    ck_assert_str_eq(name, "cliprdr");
    return available_channel;
}

static int
test_forward(struct xrdp_mm *mm, tbus channel_flags, tbus bytes, tbus data, tbus total)
{
    (void)mm;
    ck_assert_int_eq(LOWORD(channel_flags), 7);
    ck_assert_int_eq(HIWORD(channel_flags), 3);
    ck_assert_int_eq(bytes, total);
    ck_assert_int_le(bytes, sizeof(forwarded));
    memcpy(forwarded, (const void *)data, bytes);
    forwarded_size = bytes;
    ++forward_count;
    return 0;
}

static int
test_invalidate(struct xrdp_bitmap *edit, struct xrdp_rect *rect)
{
    (void)edit;
    (void)rect;
    ++invalidations;
    return 0;
}

static void
fixture_init(struct clip_fixture *f)
{
    memset(f, 0, sizeof(*f));
    send_count = forward_count = invalidations = 0;
    available_channel = 7;
    fail_allocation = 0;
    f->wm.session = &f->session;
    f->wm.client_info = &f->client;
    f->wm.xrdp_config = &f->config;
    f->config.cfg_globals.ls_clipboard = 1;
    f->client.channels_allowed = 1;
    f->wm.mm = &f->mm;
    f->mm.wm = &f->wm;
    f->mm.use_chansrv = 1;
    f->wm.login_state = WMLS_USER_PROMPT;
    f->wm.login_state_event = g_create_wait_obj(NULL);
    f->wm.login_window = f->wm.focused_window = &f->window;
    f->window.focused_control = &f->edit;
    f->window.type = WND_TYPE_WND;
    f->window.wm = f->edit.wm = &f->wm;
    f->edit.type = WND_TYPE_EDIT;
    f->edit.caption1 = f->caption;
    f->edit.caption_bytes = sizeof(f->caption);
    f->process.wm = &f->wm;
    f->wm.pro_layer = &f->process;
}

static void
fixture_free(struct clip_fixture *f)
{
    xrdp_login_clipboard_delete(&f->wm);
    ck_assert_ptr_null(f->wm.login_clipboard);
    g_delete_wait_obj(f->wm.login_state_event);
    OPENSSL_cleanse(f->caption, sizeof(f->caption));
}

static void
assert_wiped(const void *data, unsigned int bytes)
{
    const unsigned char *p = data;
    unsigned int i;
    unsigned int any = 0;
    for (i = 0; i < bytes; ++i)
    {
        any |= p[i];
    }
    ck_assert_uint_eq(any, 0);
}

static void
feed(struct clip_fixture *f, int type, int flags,
     const unsigned char *data, unsigned int bytes, int split)
{
    unsigned char packet[LOGIN_CLIP_MAX_PDU];
    struct stream s;
    memset(&s, 0, sizeof(s));
    s.data = s.p = (char *)packet;
    ck_assert_int_le(bytes + 8, sizeof(packet));
    out_uint16_le(&s, type);
    out_uint16_le(&s, flags);
    out_uint32_le(&s, bytes);
    if (bytes != 0)
    {
        out_uint8a(&s, data, bytes);
    }
    if (split > 0)
    {
        ck_assert_int_eq(xrdp_login_clipboard_data(&f->wm, 7, 1,
                                                  (char *)packet, split, bytes + 8), 1);
        assert_wiped(packet, split);
    }
    ck_assert_int_eq(xrdp_login_clipboard_data(&f->wm, 7, split > 0 ? 2 : 3,
                                              (char *)packet + split, bytes + 8 - split, bytes + 8), 1);
    assert_wiped(packet, bytes + 8);
    assert_wiped(f->wm.login_clipboard->buffer, LOGIN_CLIP_MAX_PDU);
}

static void
advertise(struct clip_fixture *f, int long_names)
{
    unsigned char caps[] = {1, 0, 0, 0, 1, 0, 12, 0, 2, 0, 0, 0, 2, 0, 0, 0};
    unsigned char formats[36] = {CF_UNICODETEXT};
    caps[12] = long_names ? CB_USE_LONG_FORMAT_NAMES : 0;
    feed(f, CB_CLIP_CAPS, 0, caps, sizeof(caps), 0);
    feed(f, CB_FORMAT_LIST, 0, formats, long_names ? 6 : sizeof(formats), 0);
    ck_assert_int_eq(f->wm.login_clipboard->unicode_available, 1);
}

static void
request(struct clip_fixture *f)
{
    xrdp_wm_key(&f->wm, 0, 29);
    xrdp_wm_key(&f->wm, 0, 47);
    xrdp_wm_key(&f->wm, KBD_FLAG_UP, 47);
    xrdp_wm_key(&f->wm, KBD_FLAG_UP, 29);
    ck_assert_uint_eq(read16(sent), CB_FORMAT_DATA_REQUEST);
    ck_assert_uint_eq(read32(sent + 8), CF_UNICODETEXT);
}

START_TEST(test_clip_opt_in)
{
    struct clip_fixture f;
    fixture_init(&f);
    f.config.cfg_globals.ls_clipboard = 0;
    xrdp_login_clipboard_init(&f.wm);
    ck_assert_ptr_null(f.wm.login_clipboard);
    f.config.cfg_globals.ls_clipboard = 1;
    f.client.channels_allowed = 0;
    xrdp_login_clipboard_init(&f.wm);
    ck_assert_ptr_null(f.wm.login_clipboard);
    f.client.channels_allowed = 1;
    available_channel = -1;
    xrdp_login_clipboard_init(&f.wm);
    ck_assert_ptr_null(f.wm.login_clipboard);
    available_channel = 7;
    f.client.rdp_autologin = 1;
    xrdp_login_clipboard_init(&f.wm);
    ck_assert_ptr_null(f.wm.login_clipboard);
    ck_assert_int_eq(send_count, 0);
    fixture_free(&f);
}
END_TEST

START_TEST(test_clip_configuration)
{
    struct xrdp_config config = {0};
    char path[] = "/tmp/xrdp-clipboard-config-XXXXXX";
    const char enabled[] = "[Globals]\nls_clipboard=true\n";
    const char defaults[] = "[Globals]\n";
    int fd = mkstemp(path);
    ck_assert_int_ge(fd, 0);
    ck_assert_int_eq(write(fd, defaults, sizeof(defaults) - 1), sizeof(defaults) - 1);
    config.cfg_globals.ls_clipboard = 1;
    ck_assert_int_eq(load_xrdp_config(&config, path, 24), 0);
    ck_assert_int_eq(config.cfg_globals.ls_clipboard, 0);
    ck_assert_int_eq(ftruncate(fd, 0), 0);
    ck_assert_int_eq(lseek(fd, 0, SEEK_SET), 0);
    ck_assert_int_eq(write(fd, enabled, sizeof(enabled) - 1), sizeof(enabled) - 1);
    ck_assert_int_eq(load_xrdp_config(&config, path, 24), 0);
    ck_assert_int_eq(config.cfg_globals.ls_clipboard, 1);
    close(fd);
    unlink(path);
}
END_TEST

START_TEST(test_clip_allocation_failure)
{
    struct clip_fixture f;
    fixture_init(&f);
    fail_allocation = 1;
    xrdp_login_clipboard_init(&f.wm);
    ck_assert_ptr_null(f.wm.login_clipboard);
    ck_assert_int_eq(send_count, 0);
    ck_assert_int_eq(xrdp_login_clipboard_data(&f.wm, 7, 3, NULL, 0, 0), 0);
    ck_assert_int_eq(xrdp_login_clipboard_key(&f.wm, 47, 0), 0);
    fail_allocation = 0;
    fixture_free(&f);
}
END_TEST

START_TEST(test_clip_stable_keyboard_modifiers)
{
    struct clip_fixture f;
    const unsigned char text[] = {'x', 0, 0, 0};
    fixture_init(&f);
    xrdp_login_clipboard_init(&f.wm);
    advertise(&f, 1);
    f.wm.keys[29] = 1 | KBD_FLAG_EXT; /* Right Ctrl shares slot 29. */
    ck_assert_int_eq(xrdp_login_clipboard_key(&f.wm, 47, 0), 1);
    ck_assert_int_eq(f.wm.login_clipboard->outstanding, 1);
    feed(&f, CB_FORMAT_DATA_RESPONSE, CB_RESPONSE_OK, text, sizeof(text), 0);
    ck_assert_int_eq(strlen(f.caption), 1);
    f.wm.keys[56] = 1 | KBD_FLAG_EXT; /* AltGr must not request clipboard. */
    ck_assert_int_eq(xrdp_login_clipboard_key(&f.wm, 47, 0), 0);
    ck_assert_int_eq(f.wm.login_clipboard->outstanding, 0);
    f.wm.keys[29] = f.wm.keys[56] = 0;
    f.wm.keys[42] = 1;
    f.wm.num_lock = 1;
    ck_assert_int_eq(xrdp_login_clipboard_key(&f.wm, 82, 0), 0);
    ck_assert_int_eq(xrdp_login_clipboard_key(&f.wm, 82, KBD_FLAG_EXT), 1);
    ck_assert_int_eq(f.wm.login_clipboard->outstanding, 1);
    ck_assert_int_eq(xrdp_login_clipboard_key(&f.wm, 82, KBD_FLAG_EXT | KBD_FLAG_UP), 1);
    feed(&f, CB_FORMAT_DATA_RESPONSE, CB_RESPONSE_OK, text, sizeof(text), 0);
    f.wm.num_lock = 0;
    ck_assert_int_eq(xrdp_login_clipboard_key(&f.wm, 82, 0), 1);
    ck_assert_int_eq(f.wm.login_clipboard->outstanding, 1);
    feed(&f, CB_FORMAT_DATA_RESPONSE, CB_RESPONSE_OK, text, sizeof(text), 0);
    ck_assert_int_eq(strlen(f.caption), 3);
    fixture_free(&f);
}
END_TEST

START_TEST(test_clip_handshake_and_receive_only)
{
    struct clip_fixture f;
    unsigned char format[] = {CF_UNICODETEXT, 0, 0, 0};
    fixture_init(&f);
    xrdp_login_clipboard_init(&f.wm);
    ck_assert_int_eq(send_count, 2);
    ck_assert_int_eq(sent_size, 8);
    ck_assert_uint_eq(read16(sent), CB_MONITOR_READY);
    advertise(&f, 0);
    ck_assert_uint_eq(read16(sent), CB_FORMAT_LIST_RESPONSE);
    ck_assert_uint_eq(read16(sent + 2), CB_RESPONSE_OK);
    ck_assert_int_eq(send_count, 3); /* No eager clipboard-content request. */
    strcpy(f.caption, "field-must-not-be-exported");
    feed(&f, CB_FORMAT_DATA_REQUEST, 0, format, sizeof(format), 0);
    ck_assert_int_eq(sent_size, 8);
    ck_assert_uint_eq(read16(sent), CB_FORMAT_DATA_RESPONSE);
    ck_assert_uint_eq(read16(sent + 2), CB_RESPONSE_FAIL);
    fixture_free(&f);
}
END_TEST

START_TEST(test_clip_ctrl_v_unicode_at_cursor)
{
    struct clip_fixture f;
    const unsigned char text[] = {0xe9, 0, 0x3d, 0xd8, 0x10, 0xdd, '!', 0, 0, 0};
    fixture_init(&f);
    xrdp_login_clipboard_init(&f.wm);
    advertise(&f, 1);
    strcpy(f.caption, "ab");
    f.edit.edit_pos = 1;
    f.edit.password_char = '*';
    request(&f);
    {
        int count = send_count;
        request(&f);
        ck_assert_int_eq(send_count, count); /* One wire request, even on key repeat. */
    }
    ck_assert_str_eq(f.caption, "ab");
    feed(&f, CB_FORMAT_DATA_RESPONSE, CB_RESPONSE_OK, text, sizeof(text), 1);
    ck_assert_str_eq(f.caption, "aé🔐!b");
    ck_assert_int_eq(f.edit.edit_pos, 4);
    ck_assert_int_eq(f.edit.password_char, '*');
    ck_assert_int_eq(invalidations, 1);
    ck_assert_ptr_null(f.wm.login_clipboard->target);
    ck_assert_int_eq(f.wm.login_clipboard->outstanding, 0);
    fixture_free(&f);
}
END_TEST

START_TEST(test_clip_shift_insert_long_password)
{
    struct clip_fixture f;
    unsigned char text[338];
    char expected[256] = "";
    unsigned char pattern[] = {'A', 0, 'a', 0, '!', 0, 0xe9, 0, 0x3d, 0xd8, 0x10, 0xdd};
    unsigned int i;
    fixture_init(&f);
    xrdp_login_clipboard_init(&f.wm);
    advertise(&f, 1);
    for (i = 0; i < 28; ++i)
    {
        memcpy(text + i * sizeof(pattern), pattern, sizeof(pattern));
        strcat(expected, "Aa!é🔐");
    }
    text[336] = text[337] = 0;
    xrdp_wm_key(&f.wm, 0, 54);
    xrdp_wm_key(&f.wm, KBD_FLAG_EXT, 82);
    xrdp_wm_key(&f.wm, KBD_FLAG_UP, 54);
    ck_assert_int_eq(f.wm.login_clipboard->outstanding, 1);
    feed(&f, CB_FORMAT_DATA_RESPONSE, CB_RESPONSE_OK, text, sizeof(text), 121);
    ck_assert_str_eq(f.caption, expected);
    ck_assert_int_eq(strlen(f.caption), 252);
    fixture_free(&f);
}
END_TEST

START_TEST(test_clip_reject_invalid_or_oversize_text)
{
    struct clip_fixture f;
    unsigned char text[514];
    const unsigned char invalid[][8] = {
        {0, 0xd8, 'a', 0, 0, 0, 0, 0}, /* unmatched high surrogate */
        {0, 0xdc, 'a', 0, 0, 0, 0, 0}, /* unmatched low surrogate */
        {'a', 0, '\n', 0, 0, 0, 0, 0},
        {'a', 0, 0, 0, 'b', 0, 0, 0}, /* embedded NUL */
        {'a', 0, 'b', 0, 'c', 0, 'd', 0} /* missing terminator */
    };
    unsigned int i;
    fixture_init(&f);
    xrdp_login_clipboard_init(&f.wm);
    advertise(&f, 1);
    for (i = 0; i < sizeof(invalid) / sizeof(invalid[0]); ++i)
    {
        request(&f);
        feed(&f, CB_FORMAT_DATA_RESPONSE, CB_RESPONSE_OK, invalid[i], sizeof(invalid[i]), 0);
        ck_assert_str_eq(f.caption, "");
    }
    for (i = 0; i < sizeof(text); i += 2)
    {
        text[i] = 'x';
        text[i + 1] = 0;
    }
    text[512] = 0; /* 256 characters: reject all. */
    request(&f);
    feed(&f, CB_FORMAT_DATA_RESPONSE, CB_RESPONSE_OK, text, sizeof(text), 0);
    ck_assert_str_eq(f.caption, "");
    text[510] = 0; /* Exactly 255 bytes: supported. */
    request(&f);
    feed(&f, CB_FORMAT_DATA_RESPONSE, CB_RESPONSE_OK, text, 512, 0);
    ck_assert_int_eq(strlen(f.caption), 255);
    request(&f);
    feed(&f, CB_FORMAT_DATA_RESPONSE, CB_RESPONSE_OK, text, 4, 0);
    ck_assert_int_eq(strlen(f.caption), 255); /* Never partially insert. */
    fixture_free(&f);
}
END_TEST

START_TEST(test_clip_cancel_focus_format_and_submit)
{
    struct clip_fixture f;
    const unsigned char text[] = {'s', 0, 0, 0};
    fixture_init(&f);
    xrdp_login_clipboard_init(&f.wm);
    advertise(&f, 1);
    request(&f);
    f.window.focused_control = NULL;
    feed(&f, CB_FORMAT_DATA_RESPONSE, CB_RESPONSE_OK, text, sizeof(text), 0);
    ck_assert_str_eq(f.caption, "");
    f.window.focused_control = &f.edit;
    request(&f);
    advertise(&f, 1); /* Clipboard changed while awaiting a reply. */
    feed(&f, CB_FORMAT_DATA_RESPONSE, CB_RESPONSE_OK, text, sizeof(text), 0);
    ck_assert_str_eq(f.caption, "");
    request(&f);
    xrdp_wm_set_login_state(&f.wm, WMLS_START_CONNECT);
    feed(&f, CB_FORMAT_DATA_RESPONSE, CB_RESPONSE_OK, text, sizeof(text), 0);
    ck_assert_str_eq(f.caption, "");
    fixture_free(&f);
}
END_TEST

START_TEST(test_clip_bad_framing_and_timeout)
{
    struct clip_fixture f;
    unsigned char start[] = {CB_FORMAT_DATA_RESPONSE, 0, CB_RESPONSE_OK, 0, 4, 0, 0, 0, 'x', 0};
    char tail[2] = {0, 0};
    int timeout = -1;
    fixture_init(&f);
    xrdp_login_clipboard_init(&f.wm);
    advertise(&f, 1);
    request(&f);
    ck_assert_int_eq(xrdp_login_clipboard_data(&f.wm, 7, 1, (char *)start, sizeof(start), 12), 1);
    xrdp_login_clipboard_wait(&f.wm, &timeout);
    ck_assert_int_ge(timeout, 0);
    ck_assert_int_le(timeout, 5000);
    f.wm.login_clipboard->rx_started -= 5001;
    xrdp_login_clipboard_check(&f.wm);
    assert_wiped(f.wm.login_clipboard->buffer, LOGIN_CLIP_MAX_PDU);
    ck_assert_int_eq(f.wm.login_clipboard->outstanding, 1);
    ck_assert_int_eq(xrdp_login_clipboard_data(&f.wm, 7, 2, tail, sizeof(tail), 12), 1);
    ck_assert_int_eq(f.wm.login_clipboard->outstanding, 0);
    ck_assert_str_eq(f.caption, "");
    memset(start, 0, sizeof(start));
    ck_assert_int_eq(xrdp_login_clipboard_data(&f.wm, 7, 3, (char *)start, sizeof(start), LOGIN_CLIP_MAX_PDU + 1), 1);
    ck_assert_str_eq(f.caption, "");
    fixture_free(&f);
}
END_TEST

START_TEST(test_clip_late_response_is_not_session_clipboard)
{
    struct clip_fixture f;
    const unsigned char text[] = {'s', 0, 'e', 0, 'c', 0, 'r', 0, 'e', 0, 't', 0, 0, 0};
    char session_request[] = {CB_FORMAT_DATA_REQUEST, 0, 0, 0, 4, 0, 0, 0, CF_UNICODETEXT, 0, 0, 0};
    const unsigned char formats[] = {CF_UNICODETEXT, 0, 0, 0, 0, 0};
    fixture_init(&f);
    xrdp_login_clipboard_init(&f.wm);
    advertise(&f, 1);
    request(&f);
    xrdp_login_clipboard_handoff(&f.wm);
    feed(&f, CB_FORMAT_LIST, 0, formats, sizeof(formats), 0);
    ck_assert_int_eq(forward_count, 1);
    ck_assert_uint_eq(read16(forwarded), CB_FORMAT_LIST);
    ck_assert_int_eq(xrdp_login_clipboard_channel_out(&f.wm, 7, 3, session_request, sizeof(session_request)), 1);
    ck_assert_uint_eq(read16(forwarded), CB_FORMAT_DATA_RESPONSE);
    ck_assert_uint_eq(read16(forwarded + 2), CB_RESPONSE_FAIL);
    ck_assert_int_eq(forwarded_size, 8);
    feed(&f, CB_FORMAT_DATA_RESPONSE, CB_RESPONSE_OK, text, sizeof(text), 9);
    ck_assert_int_eq(forward_count, 2); /* Only list and failure, never the secret. */
    ck_assert_str_eq(f.caption, "");
    ck_assert_int_eq(xrdp_login_clipboard_channel_out(&f.wm, 7, 3, session_request, sizeof(session_request)), 0);
    ck_assert_int_eq(xrdp_login_clipboard_key(&f.wm, 47, 0), 0);
    fixture_free(&f);
}
END_TEST

START_TEST(test_clip_session_route_to_chansrv)
{
    struct clip_fixture f;
    int sockets[2];
    unsigned char packet[] = {CB_FORMAT_DATA_RESPONSE, 0, CB_RESPONSE_OK, 0, 4, 0, 0, 0, 'x', 0, 0, 0};
    unsigned char received[38];
    fixture_init(&f);
    xrdp_login_clipboard_init(&f.wm);
    xrdp_login_clipboard_handoff(&f.wm);
    ck_assert_int_eq(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets), 0);
    f.mm.mod = &f.mod;
    f.mm.chan_trans = trans_create(TRANS_MODE_UNIX, 8192, 8192);
    ck_assert_ptr_nonnull(f.mm.chan_trans);
    f.mm.chan_trans->sck = sockets[0];
    f.mm.chan_trans->status = TRANS_STATUS_UP;
    ck_assert_int_eq(callback((intptr_t)&f.process, 0x5555, MAKELONG(7, 3), sizeof(packet),
                              (intptr_t)packet, sizeof(packet)), 0);
    ck_assert_int_eq(recv(sockets[1], received, sizeof(received), MSG_WAITALL), sizeof(received));
    ck_assert_uint_eq(read32(received + 8), 5); /* chansrv channel-data IPC */
    ck_assert_uint_eq(read16(received + 16), 7);
    ck_assert_uint_eq(read16(received + 18), 3);
    ck_assert_uint_eq(read16(received + 20), sizeof(packet));
    ck_assert_mem_eq(received + 26, packet, sizeof(packet));
    trans_delete(f.mm.chan_trans);
    close(sockets[1]);
    fixture_free(&f);
}
END_TEST

START_TEST(test_clip_handoff_during_fragmented_reply)
{
    struct clip_fixture f;
    unsigned char start[] = {CB_FORMAT_DATA_RESPONSE, 0, CB_RESPONSE_OK, 0, 6, 0, 0, 0, 's', 0};
    char tail[] = {'x', 0, 0, 0};
    fixture_init(&f);
    xrdp_login_clipboard_init(&f.wm);
    advertise(&f, 1);
    request(&f);
    ck_assert_int_eq(xrdp_login_clipboard_data(&f.wm, 7, 1, (char *)start, sizeof(start), 14), 1);
    xrdp_login_clipboard_cancel(&f.wm);
    assert_wiped(f.wm.login_clipboard->buffer + 8, LOGIN_CLIP_MAX_PDU - 8);
    xrdp_login_clipboard_handoff(&f.wm);
    assert_wiped(f.wm.login_clipboard->buffer + 8, LOGIN_CLIP_MAX_PDU - 8);
    /* Continuation headers' total length is ignored per VC reassembly rules. */
    ck_assert_int_eq(xrdp_login_clipboard_data(&f.wm, 7, 2, tail, sizeof(tail), 0), 1);
    ck_assert_int_eq(f.wm.login_clipboard->outstanding, 0);
    ck_assert_int_eq(forward_count, 0);
    assert_wiped(f.wm.login_clipboard->buffer, LOGIN_CLIP_MAX_PDU);
    ck_assert_str_eq(f.caption, "");
    fixture_free(&f);
}
END_TEST

START_TEST(test_clip_malformed_corpus)
{
    struct clip_fixture f;
    unsigned char packet[264];
    unsigned int random = 0x816862;
    unsigned int i;
    fixture_init(&f);
    xrdp_login_clipboard_init(&f.wm);
    for (i = 0; i < 4096; ++i)
    {
        unsigned int j;
        unsigned int bytes = 8 + i % 257;
        for (j = 0; j < bytes; ++j)
        {
            random = random * 1664525U + 1013904223U;
            packet[j] = random >> 24;
        }
        packet[0] = i % 12;
        packet[1] = 0;
        /* Alternate valid and deliberately nonsensical header dataLen. */
        if (i & 1)
        {
            packet[4] = bytes - 8;
            packet[5] = packet[6] = packet[7] = 0;
        }
        ck_assert_int_eq(xrdp_login_clipboard_data(&f.wm, 7, 3,
                                                  (char *)packet, bytes, bytes), 1);
        assert_wiped(packet, bytes);
        assert_wiped(f.wm.login_clipboard->buffer, LOGIN_CLIP_MAX_PDU);
        ck_assert_str_eq(f.caption, "");
    }
    fixture_free(&f);
}
END_TEST

START_TEST(test_clip_small_edit_allocation)
{
    struct xrdp_bitmap *edit = xrdp_bitmap_create(1, 1, 24, WND_TYPE_EDIT, NULL);
    ck_assert_ptr_nonnull(edit);
    edit->caption1 = g_strdup("x");
    ck_assert_ptr_nonnull(edit->caption1);
    xrdp_bitmap_delete(edit);
}
END_TEST

START_TEST(test_clip_request_deadline)
{
    struct clip_fixture f;
    int timeout = -1;
    const unsigned char text[] = {'x', 0, 0, 0};
    fixture_init(&f);
    xrdp_login_clipboard_init(&f.wm);
    advertise(&f, 1);
    request(&f);
    f.wm.login_clipboard->request_started -= 5001;
    xrdp_login_clipboard_wait(&f.wm, &timeout);
    ck_assert_int_eq(timeout, 0);
    feed(&f, CB_FORMAT_DATA_RESPONSE, CB_RESPONSE_OK, text, sizeof(text), 0);
    ck_assert_int_eq(strlen(f.caption), 0);
    ck_assert_ptr_null(f.wm.login_clipboard->target);
    ck_assert_int_eq(f.wm.login_clipboard->outstanding, 0);
    request(&f); /* An explicit paste is possible after the stale reply drains. */
    feed(&f, CB_FORMAT_DATA_RESPONSE, CB_RESPONSE_OK, text, sizeof(text), 0);
    ck_assert_int_eq(strlen(f.caption), 1);
    fixture_free(&f);
}
END_TEST

static int
module_long_wait(struct xrdp_mod *mod, tbus *read_objs, int *read_count,
                 tbus *write_objs, int *write_count, int *timeout)
{
    (void)mod;
    (void)read_objs;
    (void)read_count;
    (void)write_objs;
    (void)write_count;
    *timeout = 60000;
    return 0;
}

START_TEST(test_clip_wait_deadline_after_module)
{
    struct clip_fixture f;
    char start[] = {CB_FORMAT_DATA_RESPONSE, 0, CB_RESPONSE_OK, 0, 4, 0, 0, 0, 'x', 0};
    tbus read_objs[8];
    tbus write_objs[8];
    int read_count = 0;
    int write_count = 0;
    int timeout = -1;
    fixture_init(&f);
    xrdp_login_clipboard_init(&f.wm);
    advertise(&f, 1);
    request(&f);
    xrdp_login_clipboard_data(&f.wm, 7, XR_CHANNEL_FLAG_FIRST, start, sizeof(start), 12);
    f.wm.login_clipboard->rx_started -= 5001;
    xrdp_wm_set_login_state(&f.wm, WMLS_START_CONNECT);
    f.mm.mod = &f.mod;
    f.mod.mod_get_wait_objs = module_long_wait;
    ck_assert_int_eq(xrdp_wm_get_wait_objs(&f.wm, read_objs, &read_count,
                                          write_objs, &write_count, &timeout), 0);
    ck_assert_int_eq(timeout, 0);
    xrdp_login_clipboard_check(&f.wm);
    assert_wiped(f.wm.login_clipboard->buffer, LOGIN_CLIP_MAX_PDU);
    fixture_free(&f);
}
END_TEST

START_TEST(test_clip_fragmented_outbound_request)
{
    struct clip_fixture f;
    char packet[] = {CB_FORMAT_DATA_REQUEST, 0, 0, 0, 4, 0, 0, 0, CF_UNICODETEXT, 0, 0, 0};
    const unsigned char text[] = {'x', 0, 0, 0};
    fixture_init(&f);
    xrdp_login_clipboard_init(&f.wm);
    advertise(&f, 1);
    request(&f);
    xrdp_login_clipboard_handoff(&f.wm);
    ck_assert_int_eq(xrdp_login_clipboard_channel_out(&f.wm, 7, 1, packet, 1), 1);
    feed(&f, CB_FORMAT_DATA_RESPONSE, CB_RESPONSE_OK, text, sizeof(text), 0);
    ck_assert_int_eq(xrdp_login_clipboard_channel_out(&f.wm, 7, 2, packet + 1, 11), 1);
    ck_assert_int_eq(forward_count, 1);
    ck_assert_uint_eq(read16(forwarded), CB_FORMAT_DATA_RESPONSE);
    ck_assert_uint_eq(read16(forwarded + 2), CB_RESPONSE_FAIL);
    ck_assert_int_eq(xrdp_login_clipboard_channel_out(&f.wm, 7, 3, packet, 12), 0);
    fixture_free(&f);
}
END_TEST

START_TEST(test_clip_destroyed_field)
{
    struct clip_fixture f;
    struct xrdp_bitmap *edit;
    const unsigned char text[] = {'x', 0, 0, 0};
    fixture_init(&f);
    xrdp_login_clipboard_init(&f.wm);
    advertise(&f, 1);
    edit = xrdp_bitmap_create(1, 1, 24, WND_TYPE_EDIT, &f.wm);
    ck_assert_ptr_nonnull(edit);
    edit->caption1 = g_malloc(256, 1);
    edit->caption_bytes = 256;
    edit->parent = &f.window;
    f.window.child_list = list_create();
    list_add_item(f.window.child_list, (tbus)edit);
    f.window.focused_control = edit;
    request(&f);
    xrdp_bitmap_delete(edit);
    ck_assert_ptr_null(f.window.focused_control);
    ck_assert_ptr_null(f.wm.login_clipboard->target);
    feed(&f, CB_FORMAT_DATA_RESPONSE, CB_RESPONSE_OK, text, sizeof(text), 0);
    ck_assert_int_eq(invalidations, 0);
    list_delete(f.window.child_list);
    fixture_free(&f);
}
END_TEST

START_TEST(test_clip_connection_isolation)
{
    struct clip_fixture first;
    struct clip_fixture second;
    const unsigned char text[] = {'x', 0, 0, 0};
    fixture_init(&first);
    xrdp_login_clipboard_init(&first.wm);
    advertise(&first, 1);
    request(&first);
    fixture_init(&second);
    xrdp_login_clipboard_init(&second.wm);
    advertise(&second, 1);
    feed(&second, CB_FORMAT_DATA_RESPONSE, CB_RESPONSE_OK, text, sizeof(text), 0);
    ck_assert_int_eq(strlen(second.caption), 0);
    ck_assert_int_eq(strlen(first.caption), 0);
    feed(&first, CB_FORMAT_DATA_RESPONSE, CB_RESPONSE_OK, text, sizeof(text), 0);
    ck_assert_int_eq(strlen(first.caption), 1);
    fixture_free(&first);
    first.process.wm = NULL;
    ck_assert_int_eq(callback((intptr_t)&first.process, 0x5555, MAKELONG(7, 3), 0, 0, 0), 0);
    fixture_free(&second);
}
END_TEST

START_TEST(test_clip_extreme_framing)
{
    struct clip_fixture f;
    char bytes[8] = {0};
    const int totals[] = {0, -1, INT_MIN, INT_MAX, LOGIN_CLIP_MAX_PDU + 1};
    unsigned int i;
    fixture_init(&f);
    xrdp_login_clipboard_init(&f.wm);
    for (i = 0; i < sizeof(totals) / sizeof(totals[0]); ++i)
    {
        memset(bytes, 0, sizeof(bytes));
        ck_assert_int_eq(xrdp_login_clipboard_data(&f.wm, 7, 3, bytes, sizeof(bytes), totals[i]), 1);
        assert_wiped(f.wm.login_clipboard->buffer, LOGIN_CLIP_MAX_PDU);
    }
    ck_assert_int_eq(xrdp_login_clipboard_data(&f.wm, 7, 3, NULL, 0, 0), 1);
    ck_assert_int_eq(xrdp_login_clipboard_data(&f.wm, 7, 3, bytes, -1, 8), 1);
    /* A bounded actual fragment paired with a huge declared body length. */
    memset(bytes, 255, sizeof(bytes));
    ck_assert_int_eq(xrdp_login_clipboard_data(&f.wm, 7, 3, bytes, sizeof(bytes), sizeof(bytes)), 1);
    ck_assert_int_eq(strlen(f.caption), 0);
    fixture_free(&f);
}
END_TEST

START_TEST(test_clip_small_packet_work_bound)
{
    struct clip_fixture f;
    unsigned long long before;
    unsigned int i;
    fixture_init(&f);
    xrdp_login_clipboard_init(&f.wm);
    before = cleansed_bytes;
    for (i = 0; i < 1024; ++i)
    {
        char packet[8] = {0};
        xrdp_login_clipboard_data(&f.wm, 7, 3, packet, 8, 8);
    }
    ck_assert_msg(cleansed_bytes - before <= 32768, "Small PDUs cause excessive scrub work");
    fixture_free(&f);
}
END_TEST

START_TEST(test_chansrvport_validation_only)
{
    char path[32];
    ck_assert_int_eq(xrdp_mm_parse_chansrvport("/tmp/test.socket", NULL, 0, -1), 0);
    ck_assert_int_eq(xrdp_mm_parse_chansrvport("/tmp/test.socket", path, sizeof(path), -1), 0);
    ck_assert_int_eq(strcmp(path, "/tmp/test.socket"), 0);
    ck_assert_int_eq(xrdp_mm_parse_chansrvport("DISPLAY(10)", NULL, 0, -1), 0);
}
END_TEST

START_TEST(test_clip_repeated_large_paste)
{
    struct clip_fixture f;
    unsigned char text[6002];
    unsigned int i;
    fixture_init(&f);
    xrdp_login_clipboard_init(&f.wm);
    advertise(&f, 1);
    for (i = 0; i < sizeof(text) - 2; i += 2)
    {
        text[i] = 'x';
        text[i + 1] = 0;
    }
    text[6000] = text[6001] = 0;
    for (i = 0; i < 256; ++i)
    {
        request(&f);
        feed(&f, CB_FORMAT_DATA_RESPONSE, CB_RESPONSE_OK, text, sizeof(text), 1000);
        ck_assert_int_eq(strlen(f.caption), 0);
        ck_assert_int_eq(f.wm.login_clipboard->outstanding, 0);
        assert_wiped(f.wm.login_clipboard->buffer, LOGIN_CLIP_MAX_PDU);
    }
    fixture_free(&f);
}
END_TEST

START_TEST(test_clip_legacy_deleted_secret)
{
    struct clip_fixture f;
    fixture_init(&f);
    f.edit.password_char = '*';
    strcpy(f.caption, "x🔐");
    ck_assert_int_gt(xrdp_bitmap_edit_remove_char(&f.edit, 1), 0);
    ck_assert_int_eq(strcmp(f.caption, "x"), 0);
    assert_wiped(f.caption + 1, sizeof(f.caption) - 1);
    strcpy(f.caption, "éabc");
    ck_assert_int_gt(xrdp_bitmap_edit_remove_char(&f.edit, 0), 0);
    ck_assert_int_eq(strcmp(f.caption, "abc"), 0);
    assert_wiped(f.caption + 3, sizeof(f.caption) - 3);
    fixture_free(&f);
}
END_TEST

START_TEST(test_clip_retry_disconnect_lifecycle)
{
    unsigned int i;
    const unsigned char text[] = {'x', 0, 0, 0};
    for (i = 0; i < 100; ++i)
    {
        struct clip_fixture f;
        fixture_init(&f);
        xrdp_login_clipboard_init(&f.wm);
        advertise(&f, 1);
        request(&f);
        xrdp_wm_set_login_state(&f.wm, WMLS_START_CONNECT);
        xrdp_wm_set_login_state(&f.wm, WMLS_USER_PROMPT);
        xrdp_login_clipboard_init(&f.wm);
        feed(&f, CB_FORMAT_DATA_RESPONSE, CB_RESPONSE_OK, text, sizeof(text), 0);
        ck_assert_int_eq(strlen(f.caption), 0);
        request(&f);
        feed(&f, CB_FORMAT_DATA_RESPONSE, CB_RESPONSE_OK, text, sizeof(text), 0);
        ck_assert_int_eq(strlen(f.caption), 1);
        fixture_free(&f);
        f.process.wm = NULL;
        ck_assert_int_eq(callback((intptr_t)&f.process, 0x5555, MAKELONG(7, 3), 0, 0, 0), 0);
    }
}
END_TEST

Suite *
make_suite_login_clipboard(void)
{
    Suite *suite = suite_create("login_clipboard");
    TCase *tc = tcase_create("login_clipboard");
    tcase_add_test(tc, test_clip_opt_in);
    tcase_add_test(tc, test_clip_configuration);
    tcase_add_test(tc, test_clip_allocation_failure);
    tcase_add_test(tc, test_clip_stable_keyboard_modifiers);
    tcase_add_test(tc, test_clip_handshake_and_receive_only);
    tcase_add_test(tc, test_clip_ctrl_v_unicode_at_cursor);
    tcase_add_test(tc, test_clip_shift_insert_long_password);
    tcase_add_test(tc, test_clip_reject_invalid_or_oversize_text);
    tcase_add_test(tc, test_clip_cancel_focus_format_and_submit);
    tcase_add_test(tc, test_clip_bad_framing_and_timeout);
    tcase_add_test(tc, test_clip_late_response_is_not_session_clipboard);
    tcase_add_test(tc, test_clip_session_route_to_chansrv);
    tcase_add_test(tc, test_clip_handoff_during_fragmented_reply);
    tcase_add_test(tc, test_clip_malformed_corpus);
    tcase_add_test(tc, test_clip_small_edit_allocation);
    tcase_add_test(tc, test_clip_request_deadline);
    tcase_add_test(tc, test_clip_wait_deadline_after_module);
    tcase_add_test(tc, test_clip_fragmented_outbound_request);
    tcase_add_test(tc, test_clip_destroyed_field);
    tcase_add_test(tc, test_clip_connection_isolation);
    tcase_add_test(tc, test_clip_extreme_framing);
    tcase_add_test(tc, test_clip_small_packet_work_bound);
    tcase_add_test(tc, test_chansrvport_validation_only);
    tcase_add_test(tc, test_clip_repeated_large_paste);
    tcase_add_test(tc, test_clip_legacy_deleted_secret);
    tcase_add_test(tc, test_clip_retry_disconnect_lifecycle);
    suite_add_tcase(suite, tc);
    return suite;
}

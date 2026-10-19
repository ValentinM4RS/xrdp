/* Licensed under the Apache License, Version 2.0. See COPYING. */
#include <config_ac.h>
#include "xrdp.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static unsigned int fuzz_clock;
static int fuzz_channel(struct xrdp_session *s, const char *name);
static int fuzz_send(struct xrdp_session *s, int channel, char *data, int bytes, int total, int flags);
static int fuzz_forward(struct xrdp_mm *mm, tbus a, tbus b, tbus c, tbus d);
static int fuzz_invalidate(struct xrdp_bitmap *bitmap, struct xrdp_rect *rect);
static unsigned int fuzz_time(void);
void __real_OPENSSL_cleanse(void *, size_t);
void __wrap_OPENSSL_cleanse(void *, size_t);
void *__asan_memset(void *, int, size_t);

void
__wrap_OPENSSL_cleanse(void *data, size_t bytes)
{
    /* Extend ASan's write-range checking across uninstrumented libcrypto. */
    __asan_memset(data, 0, bytes);
    __real_OPENSSL_cleanse(data, bytes);
}

#define libxrdp_get_channel_id fuzz_channel
#define libxrdp_send_to_channel fuzz_send
#define xrdp_mm_process_channel_data fuzz_forward
#define xrdp_bitmap_invalidate fuzz_invalidate
#define g_get_elapsed_ms fuzz_time
#include "../../xrdp/xrdp_login_clipboard.c"

static int fuzz_channel(struct xrdp_session *s, const char *name)
{ (void)s; (void)name; return 7; }
static int fuzz_send(struct xrdp_session *s, int channel, char *data, int bytes, int total, int flags)
{ (void)s; (void)channel; (void)data; (void)bytes; (void)total; (void)flags; return 0; }
static int fuzz_forward(struct xrdp_mm *mm, tbus a, tbus b, tbus c, tbus d)
{ (void)mm; (void)a; (void)b; (void)c; (void)d; return 0; }
static int fuzz_invalidate(struct xrdp_bitmap *bitmap, struct xrdp_rect *rect)
{ (void)bitmap; (void)rect; return 0; }
static unsigned int fuzz_time(void) { return fuzz_clock; }

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    struct xrdp_wm wm = {0};
    struct xrdp_mm mm = {0};
    struct xrdp_config config = {0};
    struct xrdp_client_info client = {0};
    struct xrdp_bitmap window = {0};
    struct xrdp_bitmap edit = {0};
    struct xrdp_login_clipboard formats = {0};
    char caption[256] = {0};
    char text[256] = {0};
    size_t position = 0;
    unsigned int records = 0;
    size_t bounded = size > LOGIN_CLIP_MAX_PDU ? LOGIN_CLIP_MAX_PDU : size;
    decode_text(data, bounded, text);
    OPENSSL_cleanse(text, sizeof(text));
    parse_caps(&formats, data, bounded);
    parse_formats(&formats, data, bounded);
    formats.long_names = 1;
    parse_formats(&formats, data, bounded);
    wm.mm = &mm;
    mm.wm = &wm;
    mm.use_chansrv = 1;
    wm.client_info = &client;
    client.channels_allowed = 1;
    wm.xrdp_config = &config;
    config.cfg_globals.ls_clipboard = 1;
    wm.login_state = WMLS_USER_PROMPT;
    wm.login_window = wm.focused_window = &window;
    window.focused_control = &edit;
    edit.type = WND_TYPE_EDIT;
    edit.caption1 = caption;
    edit.caption_bytes = sizeof(caption);
    fuzz_clock = 0;
    xrdp_login_clipboard_init(&wm);
    while (size - position >= 8 && records++ < 64)
    {
        unsigned int op = data[position++];
        int flags = data[position++];
        int total = (int)read32(data + position);
        size_t bytes;
        char *copy;
        position += 4;
        bytes = read16(data + position);
        position += 2;
        if (bytes > size - position)
        {
            bytes = size - position;
        }
        copy = malloc(bytes == 0 ? 1 : bytes);
        if (copy == NULL)
        {
            break;
        }
        memcpy(copy, data + position, bytes);
        switch (op % 8)
        {
            case 0:
                xrdp_login_clipboard_data(&wm, 7, flags, copy, bytes, total);
                break;
            case 1:
                wm.login_clipboard->unicode_available = 1;
                wm.keys[29] = 1;
                xrdp_login_clipboard_key(&wm, 47, 0);
                break;
            case 2:
                xrdp_login_clipboard_cancel(&wm);
                break;
            case 3:
                xrdp_login_clipboard_handoff(&wm);
                break;
            case 4:
                fuzz_clock += (unsigned int)total;
                xrdp_login_clipboard_check(&wm);
                break;
            case 5:
                xrdp_login_clipboard_channel_out(&wm, 7, flags, copy, bytes);
                break;
            case 6:
                xrdp_login_clipboard_delete(&wm);
                xrdp_login_clipboard_init(&wm);
                break;
            default:
                wm.focused_window = (op & 8) ? NULL : &window;
                break;
        }
        OPENSSL_cleanse(copy, bytes);
        free(copy);
        position += bytes;
    }
    xrdp_login_clipboard_delete(&wm);
    OPENSSL_cleanse(caption, sizeof(caption));
    return 0;
}

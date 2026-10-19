/**
 * xrdp: A Remote Desktop Protocol server.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Receive-only, on-demand CF_UNICODETEXT for the pre-session login UI.
 * No X11, clipboard cache, file transfer, or server clipboard ownership.
 */
#if defined(HAVE_CONFIG_H)
#include <config_ac.h>
#endif
#include "xrdp.h"
#include "xrdp_login_clipboard.h"
#include "ms-rdpbcgr.h"
#include "ms-rdpeclip.h"
#include "string_calls.h"
#include <openssl/crypto.h>
#include <string.h>

#define LOGIN_CLIP_MAX_PDU 8192
#define LOGIN_CLIP_RX_TIMEOUT 5000

struct xrdp_login_clipboard
{
    int channel;
    int handed_off;
    int long_names;
    int unicode_available;
    int outstanding;
    void *target;
    int received;
    int expected;
    int discarding;
    int discard_response;
    unsigned int rx_started;
    unsigned int request_started;
    int out_discard;
    int out_header_bytes;
    int out_response_sent;
    unsigned char out_header[2];
    unsigned char buffer[LOGIN_CLIP_MAX_PDU];
};

static unsigned int
read16(const unsigned char *p)
{
    return p[0] | ((unsigned int)p[1] << 8);
}

static unsigned int
read32(const unsigned char *p)
{
    return read16(p) | (read16(p + 2) << 16);
}

/* All outbound login PDUs are small and never contain clipboard contents. */
static int
send_pdu(struct xrdp_wm *wm, int type, int flags,
         const char *body, int bytes)
{
    char packet[32];
    struct stream s;
    if (bytes < 0 || bytes > (int)sizeof(packet) - 8 ||
            (bytes != 0 && body == NULL) || wm->login_clipboard == NULL)
    {
        return 1;
    }
    memset(&s, 0, sizeof(s));
    s.p = s.data = packet;
    out_uint16_le(&s, type);
    out_uint16_le(&s, flags);
    out_uint32_le(&s, bytes);
    if (bytes != 0)
    {
        out_uint8a(&s, body, bytes);
    }
    return libxrdp_send_to_channel(wm->session, wm->login_clipboard->channel,
                                    packet, bytes + 8, bytes + 8,
                                    XR_CHANNEL_FLAG_FIRST | XR_CHANNEL_FLAG_LAST);
}

static void
clear_rx(struct xrdp_login_clipboard *clip)
{
    /* Every byte outside received is already zero. Avoid turning tiny PDUs
     * into repeated 8 KiB writes on the unauthenticated network path. */
    OPENSSL_cleanse(clip->buffer, clip->received);
    clip->received = clip->expected = 0;
}

void
xrdp_login_clipboard_cancel(struct xrdp_wm *wm)
{
    if (wm->login_clipboard != NULL)
    {
        int had_target = wm->login_clipboard->target != NULL;
        /* A request has no wire ID. Retain outstanding until its reply is
         * drained, otherwise a late reply could satisfy a different paste. */
        wm->login_clipboard->target = NULL;
        if (had_target && wm->login_clipboard->received > 8 &&
                read16(wm->login_clipboard->buffer) == CB_FORMAT_DATA_RESPONSE)
        {
            OPENSSL_cleanse(wm->login_clipboard->buffer + 8,
                            wm->login_clipboard->received - 8);
        }
    }
}

void
xrdp_login_clipboard_delete(struct xrdp_wm *wm)
{
    if (wm->login_clipboard != NULL)
    {
        OPENSSL_cleanse(wm->login_clipboard, sizeof(*wm->login_clipboard));
        g_free(wm->login_clipboard);
        wm->login_clipboard = NULL;
    }
}

void
xrdp_login_clipboard_init(struct xrdp_wm *wm)
{
    int channel;
    /* Preserve negotiation and an outstanding reply across failed logins. */
    if (wm->login_clipboard != NULL ||
            !wm->xrdp_config->cfg_globals.ls_clipboard ||
            !wm->client_info->channels_allowed ||
            wm->client_info->rdp_autologin)
    {
        return;
    }
    channel = libxrdp_get_channel_id(wm->session, "cliprdr");
    if (channel < 0)
    {
        return;
    }
    wm->login_clipboard = g_new0(struct xrdp_login_clipboard, 1);
    if (wm->login_clipboard != NULL)
    {
        /* Disabled channels remain disabled in libxrdp; no policy is relaxed. */
        static const char caps[] = {1, 0, 0, 0, 1, 0, 12, 0,
                                   2, 0, 0, 0, CB_USE_LONG_FORMAT_NAMES, 0, 0, 0};
        wm->login_clipboard->channel = channel;
        if (send_pdu(wm, CB_CLIP_CAPS, 0, caps, sizeof(caps)) != 0 ||
                send_pdu(wm, CB_MONITOR_READY, 0, NULL, 0) != 0)
        {
            xrdp_login_clipboard_delete(wm);
        }
    }
}

/* Tokens are only compared, never dereferenced after an asynchronous request. */
static void *
paste_target(struct xrdp_wm *wm)
{
    struct xrdp_bitmap *window = wm->login_window;
    if (wm->login_state != WMLS_USER_PROMPT || wm->popup_wnd != NULL)
    {
        return NULL;
    }
    if (window != NULL && wm->focused_window == window &&
            window->modal_dialog == NULL && window->focused_control != NULL &&
            window->focused_control->type == WND_TYPE_EDIT)
    {
        return window->focused_control;
    }
    return NULL;
}

int
xrdp_login_clipboard_key(struct xrdp_wm *wm, int scancode, int flags)
{
    struct xrdp_login_clipboard *clip = wm->login_clipboard;
    /* v0.10 stores extended flags in keys[29/56], rather than separate
     * left/right modifier slots. Match its native keyboard representation. */
    int ctrl = wm->keys[29] != 0;
    int shift = wm->keys[42] || wm->keys[54];
    int alt = wm->keys[56] != 0;
    int keyup = (flags & KBD_FLAG_UP) != 0;
    int shortcut = !alt &&
                   ((ctrl && scancode == 47 && !(flags & KBD_FLAG_EXT)) ||
                    (!ctrl && shift && scancode == 82 &&
                     ((flags & KBD_FLAG_EXT) || !wm->num_lock)));
    if (clip == NULL || clip->handed_off || wm->login_state != WMLS_USER_PROMPT ||
            !wm->xrdp_config->cfg_globals.ls_clipboard)
    {
        return 0;
    }
    if (shortcut)
    {
        void *target = paste_target(wm);
        if (!keyup && target != NULL && clip->unicode_available && !clip->outstanding)
        {
            static const char format[] = {CF_UNICODETEXT, 0, 0, 0};
            clip->target = target;
            clip->outstanding = 1;
            clip->request_started = g_get_elapsed_ms();
            if (send_pdu(wm, CB_FORMAT_DATA_REQUEST, 0, format, sizeof(format)) != 0)
            {
                /* A failed write can have sent part of the request. */
                xrdp_login_clipboard_cancel(wm);
            }
        }
        return 1; /* Never insert a literal 'v' in a password field. */
    }
    if (!keyup && scancode != 29 && scancode != 42 && scancode != 54)
    {
        xrdp_login_clipboard_cancel(wm);
    }
    return 0;
}

/* Reject, rather than truncate, invalid/oversized or multi-line credentials. */
static int
decode_text(const unsigned char *data, unsigned int bytes, char text[256])
{
    unsigned int i;
    unsigned int chars = 0;
    if (bytes < 2 || (bytes & 1) || read16(data + bytes - 2) != 0)
    {
        return 0;
    }
    text[0] = '\0';
    for (i = 0; i < bytes - 2; i += 2)
    {
        char32_t cp = read16(data + i);
        if (cp >= 0xd800 && cp <= 0xdbff)
        {
            unsigned int low;
            i += 2;
            if (i >= bytes - 2 || (low = read16(data + i)) < 0xdc00 || low > 0xdfff)
            {
                return 0;
            }
            cp = 0x10000 + ((cp - 0xd800) << 10) + low - 0xdc00;
        }
        else if (cp >= 0xdc00 && cp <= 0xdfff)
        {
            return 0;
        }
        if (cp < 32 || (cp >= 0x7f && cp <= 0x9f) || cp == 0x2028 || cp == 0x2029 ||
                !utf8_add_char_at(text, 256, cp, chars++))
        {
            return 0;
        }
    }
    return 1;
}

static void
insert_text(struct xrdp_wm *wm, const char *text)
{
    struct xrdp_login_clipboard *clip = wm->login_clipboard;
    if (clip->target == NULL || clip->target != paste_target(wm))
    {
        return;
    }
    {
        struct xrdp_bitmap *edit = (struct xrdp_bitmap *)clip->target;
        unsigned int bytes = strlen(text);
        const char *cursor = edit->caption1;
        unsigned int capacity = MIN(edit->caption_bytes, 256);
        size_t existing;
        int i;
        if (cursor == NULL || capacity == 0 ||
                (existing = strnlen(cursor, capacity)) >= capacity ||
                bytes > capacity - 1 - existing || edit->edit_pos < 0)
        {
            return;
        }
        for (i = 0; i < edit->edit_pos && *cursor != '\0'; ++i)
        {
            utf8_get_next_char(&cursor, NULL);
        }
        if (i == edit->edit_pos)
        {
            memmove((char *)cursor + bytes, cursor, strlen(cursor) + 1);
            memcpy((char *)cursor, text, bytes);
            edit->edit_pos += utf8_char_count(text);
            xrdp_bitmap_invalidate(edit, NULL);
        }
    }
}

static int
parse_caps(struct xrdp_login_clipboard *clip, const unsigned char *data, unsigned int bytes)
{
    unsigned int count;
    unsigned int i;
    int long_names = 0;
    if (bytes < 4)
    {
        return 0;
    }
    count = read16(data);
    data += 4;
    bytes -= 4;
    for (i = 0; i < count; ++i)
    {
        unsigned int size;
        if (bytes < 4 || (size = read16(data + 2)) < 4 || size > bytes)
        {
            return 0;
        }
        if (read16(data) == CB_CAPSTYPE_GENERAL)
        {
            if (size < 12)
            {
                return 0;
            }
            long_names = read32(data + 4) >= CB_CAPS_VERSION_2 &&
                         (read32(data + 8) & CB_USE_LONG_FORMAT_NAMES) != 0;
        }
        data += size;
        bytes -= size;
    }
    if (bytes != 0)
    {
        return 0;
    }
    clip->long_names = long_names;
    return 1;
}

static int
parse_formats(struct xrdp_login_clipboard *clip, const unsigned char *data, unsigned int bytes)
{
    int available = 0;
    while (bytes != 0)
    {
        unsigned int size = 36; /* short format: UINT32 + 32-byte name */
        if (bytes < (clip->long_names ? 6 : 36))
        {
            return 0;
        }
        if (read32(data) == CF_UNICODETEXT)
        {
            available = 1;
        }
        if (clip->long_names)
        {
            size = 4;
            while (size + 2 <= bytes && read16(data + size) != 0)
            {
                size += 2;
            }
            if (size + 2 > bytes)
            {
                return 0;
            }
            size += 2;
        }
        data += size;
        bytes -= size;
    }
    clip->unicode_available = available;
    return 1;
}

static void
forward_pdu(struct xrdp_wm *wm, const unsigned char *data, int bytes)
{
    int channel_flags = MAKELONG(wm->login_clipboard->channel,
                                  XR_CHANNEL_FLAG_FIRST | XR_CHANNEL_FLAG_LAST);
    if (wm->mm->use_chansrv)
    {
        xrdp_mm_process_channel_data(wm->mm, channel_flags, bytes, (tbus)data, bytes);
    }
    else if (wm->mm->mod != NULL && wm->mm->mod->mod_event != NULL)
    {
        wm->mm->mod->mod_event(wm->mm->mod, WM_CHANNEL_DATA,
                               channel_flags, bytes, (tbus)data, bytes);
    }
}

static void
process_pdu(struct xrdp_wm *wm)
{
    struct xrdp_login_clipboard *clip = wm->login_clipboard;
    const unsigned char *p = clip->buffer;
    unsigned int type = read16(p);
    unsigned int flags = read16(p + 2);
    unsigned int bytes = read32(p + 4);
    unsigned int actual = clip->received - 8;
    char text[256] = {0};
    if (clip->handed_off)
    {
        if (type == CB_FORMAT_DATA_RESPONSE)
        {
            clip->outstanding = 0; /* Drain the old reply, never export it. */
        }
        else
        {
            forward_pdu(wm, p, clip->received);
        }
        return;
    }
    /* Some clients append the historical four-byte zero pad to PDUs. */
    if (bytes > actual || (actual != bytes &&
                          !(actual == bytes + 4 && read32(p + 8 + bytes) == 0)))
    {
        xrdp_login_clipboard_cancel(wm);
        return;
    }
    p += 8;
    switch (type)
    {
        case CB_CLIP_CAPS:
            if (!parse_caps(clip, p, bytes))
            {
                clip->unicode_available = 0;
            }
            break;
        case CB_FORMAT_LIST:
            xrdp_login_clipboard_cancel(wm);
            clip->unicode_available = 0;
            send_pdu(wm, CB_FORMAT_LIST_RESPONSE,
                     parse_formats(clip, p, bytes) ? CB_RESPONSE_OK : CB_RESPONSE_FAIL,
                     NULL, 0);
            break;
        case CB_FORMAT_DATA_RESPONSE:
            if (clip->outstanding && clip->target != NULL &&
                    clip->target == paste_target(wm) && flags == CB_RESPONSE_OK &&
                    decode_text(p, bytes, text))
            {
                insert_text(wm, text);
            }
            clip->outstanding = 0;
            xrdp_login_clipboard_cancel(wm);
            OPENSSL_cleanse(text, sizeof(text));
            break;
        case CB_FORMAT_DATA_REQUEST:
            /* The login UI never publishes a clipboard or its field values. */
            send_pdu(wm, CB_FORMAT_DATA_RESPONSE, CB_RESPONSE_FAIL, NULL, 0);
            break;
        default:
            /* No bitmap, file, directory, or lock support before login. */
            break;
    }
}

void
xrdp_login_clipboard_handoff(struct xrdp_wm *wm)
{
    if (wm->login_clipboard != NULL)
    {
        xrdp_login_clipboard_cancel(wm);
        wm->login_clipboard->handed_off = 1;
        wm->login_clipboard->unicode_available = 0;
        /* Retain only enough state to discard a late pre-login reply.
         * chansrv runs its own fresh capabilities/monitor-ready exchange. */
    }
}

int
xrdp_login_clipboard_channel_out(struct xrdp_wm *wm, int channel,
                                  int flags, const char *data, int bytes)
{
    struct xrdp_login_clipboard *clip = wm->login_clipboard;
    if (clip == NULL || !clip->handed_off || channel != clip->channel ||
            (!clip->outstanding && !clip->out_discard))
    {
        return 0;
    }
    if (flags & XR_CHANNEL_FLAG_FIRST)
    {
        clip->out_header_bytes = clip->out_response_sent = 0;
        clip->out_discard = bytes < 2 || data == NULL ||
                            read16((const unsigned char *)data) == CB_FORMAT_DATA_REQUEST;
    }
    if (clip->out_discard)
    {
        static const unsigned char failed[] = {CB_FORMAT_DATA_RESPONSE, 0,
                                               CB_RESPONSE_FAIL, 0, 0, 0, 0, 0};
        while (data != NULL && bytes > 0 && clip->out_header_bytes < 2)
        {
            clip->out_header[clip->out_header_bytes++] = (unsigned char)*data++;
            --bytes;
        }
        /* No request IDs exist. Do not let a session request race a pending
         * login response: report failure locally until the old reply drains. */
        if (clip->out_header_bytes == 2 && !clip->out_response_sent &&
                read16(clip->out_header) == CB_FORMAT_DATA_REQUEST)
        {
            forward_pdu(wm, failed, sizeof(failed));
            clip->out_response_sent = 1;
        }
        if (flags & XR_CHANNEL_FLAG_LAST)
        {
            clip->out_discard = 0;
        }
        return 1;
    }
    return 0;
}

int
xrdp_login_clipboard_data(struct xrdp_wm *wm, int channel, int flags,
                           char *data, int bytes, int total)
{
    struct xrdp_login_clipboard *clip = wm->login_clipboard;
    if (clip == NULL || channel != clip->channel ||
            (clip->handed_off && !clip->outstanding && clip->received == 0 && !clip->discarding))
    {
        return 0; /* Session traffic follows its original route unchanged. */
    }
    if (bytes > 0 && data == NULL)
    {
        xrdp_login_clipboard_cancel(wm);
        clear_rx(clip);
        clip->discarding = !(flags & XR_CHANNEL_FLAG_LAST);
        return 1;
    }
    xrdp_login_clipboard_check(wm);
    if (flags & XR_CHANNEL_FLAG_FIRST)
    {
        clear_rx(clip);
        clip->discarding = clip->discard_response = 0;
        clip->expected = total;
        clip->rx_started = g_get_elapsed_ms();
    }
    /* As with the common VC dechunker, only FIRST's total length is used. */
    if (bytes < 0 || clip->expected < 8 || clip->expected > LOGIN_CLIP_MAX_PDU ||
            bytes > clip->expected - clip->received ||
            bytes == 0 || clip->discarding)
    {
        clip->discarding = 1;
        if ((flags & XR_CHANNEL_FLAG_FIRST) && bytes >= 2)
        {
            clip->discard_response = read16((unsigned char *)data) == CB_FORMAT_DATA_RESPONSE;
        }
        xrdp_login_clipboard_cancel(wm);
        clear_rx(clip);
    }
    else
    {
        int start = MAX(clip->received, 8);
        memcpy(clip->buffer + clip->received, data, bytes);
        clip->received += bytes;
        if (clip->received > 8 && clip->target == NULL &&
                read16(clip->buffer) == CB_FORMAT_DATA_RESPONSE)
        {
            /* A cancelled/unsolicited paste only needs its reply header drained. */
            OPENSSL_cleanse(clip->buffer + start, clip->received - start);
        }
    }
    /* This copy is owned by the RDP receive stream, not by a desktop channel. */
    if (bytes > 0)
    {
        OPENSSL_cleanse(data, bytes);
    }
    if (flags & XR_CHANNEL_FLAG_LAST)
    {
        if (!clip->discarding && clip->received == clip->expected)
        {
            process_pdu(wm);
        }
        else
        {
            xrdp_login_clipboard_cancel(wm);
            if (clip->discard_response)
            {
                clip->outstanding = 0;
            }
        }
        clear_rx(clip);
        clip->discarding = clip->discard_response = 0;
    }
    return 1;
}

void
xrdp_login_clipboard_wait(struct xrdp_wm *wm, int *timeout)
{
    struct xrdp_login_clipboard *clip = wm->login_clipboard;
    if (clip != NULL)
    {
        unsigned int now = g_get_elapsed_ms();
        unsigned int elapsed;
        int remaining = LOGIN_CLIP_RX_TIMEOUT;
        int active = 0;
        if (clip->received != 0)
        {
            elapsed = now - clip->rx_started;
            remaining = elapsed >= LOGIN_CLIP_RX_TIMEOUT ? 0 : LOGIN_CLIP_RX_TIMEOUT - elapsed;
            active = 1;
        }
        if (clip->outstanding && clip->target != NULL)
        {
            elapsed = now - clip->request_started;
            remaining = MIN(remaining, elapsed >= LOGIN_CLIP_RX_TIMEOUT ? 0 : LOGIN_CLIP_RX_TIMEOUT - elapsed);
            active = 1;
        }
        if (active && (*timeout < 0 || *timeout > remaining))
        {
            *timeout = remaining;
        }
    }
}

void
xrdp_login_clipboard_check(struct xrdp_wm *wm)
{
    struct xrdp_login_clipboard *clip = wm->login_clipboard;
    if (clip != NULL && clip->outstanding && clip->target != NULL &&
            (unsigned int)(g_get_elapsed_ms() - clip->request_started) >= LOGIN_CLIP_RX_TIMEOUT)
    {
        xrdp_login_clipboard_cancel(wm);
    }
    if (clip != NULL && clip->received != 0 &&
            (unsigned int)(g_get_elapsed_ms() - clip->rx_started) >= LOGIN_CLIP_RX_TIMEOUT)
    {
        clip->discard_response = clip->received >= 2 &&
                                 read16(clip->buffer) == CB_FORMAT_DATA_RESPONSE;
        clip->discarding = 1;
        xrdp_login_clipboard_cancel(wm);
        clear_rx(clip);
    }
}

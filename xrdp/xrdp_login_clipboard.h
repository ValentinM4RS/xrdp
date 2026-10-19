/* Licensed under the Apache License, Version 2.0. See COPYING. */
#ifndef XRDP_LOGIN_CLIPBOARD_H
#define XRDP_LOGIN_CLIPBOARD_H

struct xrdp_wm;
void xrdp_login_clipboard_init(struct xrdp_wm *wm);
void xrdp_login_clipboard_delete(struct xrdp_wm *wm);
void xrdp_login_clipboard_cancel(struct xrdp_wm *wm);
void xrdp_login_clipboard_handoff(struct xrdp_wm *wm);
int xrdp_login_clipboard_key(struct xrdp_wm *wm, int scancode, int flags);
/* Return nonzero when the clipboard handler owns/consumes the fragment. */
int xrdp_login_clipboard_data(struct xrdp_wm *wm, int channel, int flags,
                              char *data, int bytes, int total);
int xrdp_login_clipboard_channel_out(struct xrdp_wm *wm, int channel,
                                     int flags, const char *data, int bytes);
void xrdp_login_clipboard_wait(struct xrdp_wm *wm, int *timeout);
void xrdp_login_clipboard_check(struct xrdp_wm *wm);
#endif

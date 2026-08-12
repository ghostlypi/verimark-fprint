/*
 * Microsoft Secure Device Connection Protocol (SDCP) client
 * Copyright (C) 2026 Parth
 *
 * Spec: https://github.com/microsoft/SecureDeviceConnectionProtocol
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#pragma once

#include <glib.h>
#include <gio/gio.h>

G_BEGIN_DECLS

#define SDCP_RANDOM_LEN   32
#define SDCP_PUBKEY_LEN   65      /* uncompressed P-256: 0x04 || X || Y */
#define SDCP_MAC_LEN      32
#define SDCP_SECRET_LEN   32

#define SDCP_CONNECT_MSG_LEN     101   /* [u16 32][rand][u16 65][pubkey]    */
#define SDCP_CONNECT_RESP_LEN    1206
#define SDCP_RECONNECT_MSG_LEN   34    /* [u16 32][rand]                    */
#define SDCP_RECONNECT_RESP_LEN  34    /* [u16 32][mac]                     */

typedef struct _VerimarkSdcp VerimarkSdcp;

VerimarkSdcp *vm_sdcp_new (void);
void          vm_sdcp_free (VerimarkSdcp *self);

G_DEFINE_AUTOPTR_CLEANUP_FUNC (VerimarkSdcp, vm_sdcp_free)

gboolean vm_sdcp_is_established (VerimarkSdcp *self);

/* Step 1: build the connect message (generates an ephemeral P-256 key). */
gboolean vm_sdcp_build_connect (VerimarkSdcp *self,
                                guint8       *out,
                                gsize         out_len,
                                GError      **error);

/*
 * Step 2: consume the connect response. Performs ECDH against the device's
 * *firmware* public key, runs the SP 800-108 schedule, and verifies the
 * device's ClaimMAC. A successful return proves we hold the real MAC_secret.
 */
gboolean vm_sdcp_handle_connect_response (VerimarkSdcp *self,
                                          const guint8 *resp,
                                          gsize         resp_len,
                                          GError      **error);

/* Step 3: build the reconnect message. Required before the device will
 * issue enrollment nonces. */
gboolean vm_sdcp_build_reconnect (VerimarkSdcp *self,
                                  guint8       *out,
                                  gsize         out_len,
                                  GError      **error);

/* Step 4: verify the device's ReconnectionMAC and mark the session live. */
gboolean vm_sdcp_handle_reconnect_response (VerimarkSdcp *self,
                                            const guint8 *resp,
                                            gsize         resp_len,
                                            GError      **error);

/* enrollment_id = HMAC(MAC_secret, "enroll\0" || nonce) */
gboolean vm_sdcp_enrollment_id (VerimarkSdcp *self,
                                const guint8 *nonce,
                                guint8       *out_id,
                                GError      **error);

/* AuthenticationMAC = HMAC(MAC_secret, "identify\0" || nonce || enrollment_id) */
gboolean vm_sdcp_verify_identify_mac (VerimarkSdcp *self,
                                      const guint8 *nonce,
                                      const guint8 *enrollment_id,
                                      const guint8 *mac);

void vm_sdcp_random (guint8 *buf, gsize len);

G_END_DECLS

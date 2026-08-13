/*
 * Microsoft Secure Device Connection Protocol (SDCP) client
 *
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2026, Parth Iyer
 */

#include "verimark-sdcp.h"

#include <string.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/param_build.h>
#include <openssl/core_names.h>

/*
 * Claim layout, tail-anchored so an unexpected certificate size cannot shift
 * the fields we care about:
 *   claim = certificate || DevicePublicKey(65) || FirmwarePublicKey(65)
 *           || FirmwareHash(32) || ModelSignature(64) || DeviceSignature(64)
 */
#define CLAIM_TAIL_LEN 290
#define CLAIM_FW_PUBKEY_OFF_FROM_END 225

struct _VerimarkSdcp
{
  EVP_PKEY *ephemeral;
  guint8    host_random[SDCP_RANDOM_LEN];
  guint8    device_random[SDCP_RANDOM_LEN];
  guint8    reconnect_random[SDCP_RANDOM_LEN];
  guint8    mac_secret[SDCP_SECRET_LEN];
  guint8    sym_key[SDCP_SECRET_LEN];
  gboolean  keys_derived;
  gboolean  established;
};

void
vm_sdcp_random (guint8 *buf, gsize len)
{
  if (RAND_bytes (buf, (int) len) != 1)
    {
      /* Never silently fall back to weak randomness. */
      g_error ("verimark: OpenSSL RNG failed");
    }
}

VerimarkSdcp *
vm_sdcp_new (void)
{
  return g_new0 (VerimarkSdcp, 1);
}

void
vm_sdcp_free (VerimarkSdcp *self)
{
  if (!self)
    return;
  if (self->ephemeral)
    EVP_PKEY_free (self->ephemeral);
  OPENSSL_cleanse (self->mac_secret, sizeof (self->mac_secret));
  OPENSSL_cleanse (self->sym_key, sizeof (self->sym_key));
  g_free (self);
}

gboolean
vm_sdcp_is_established (VerimarkSdcp *self)
{
  return self && self->established;
}

/*
 * NIST SP 800-108 KDF in counter mode with HMAC-SHA256:
 *   K(i) = HMAC(key, be32(i) || Label || 0x00 || Context || be32(L))
 * The label's NUL terminator is part of the input.
 */
static gboolean
hmac_sha256 (const guint8 *key, gsize key_len,
             const guint8 *data, gsize data_len,
             guint8 *out)
{
  unsigned int len = SHA256_DIGEST_LENGTH;

  return HMAC (EVP_sha256 (), key, (int) key_len, data, data_len, out, &len) != NULL &&
         len == SHA256_DIGEST_LENGTH;
}

static gboolean
sp800108_kdf (const guint8 *key, gsize key_len,
              const gchar  *label,
              const guint8 *context, gsize context_len,
              guint32       out_bits,
              guint8       *out, gsize out_len)
{
  gsize label_len = strlen (label) + 1;      /* the NUL is part of the input */
  guint32 blocks = (out_bits + 255) / 256;
  guint32 l_be = GUINT32_TO_BE (out_bits);
  gsize want = out_bits / 8;
  gsize produced = 0;
  gsize msg_len = 4 + label_len + context_len + 4;
  g_autofree guint8 *msg = NULL;

  g_return_val_if_fail (out_len >= want, FALSE);

  /* K(i) = HMAC(key, be32(i) || Label || 0x00 || Context || be32(L)) */
  msg = g_malloc (msg_len);
  memcpy (msg + 4, label, label_len);
  if (context_len)
    memcpy (msg + 4 + label_len, context, context_len);
  memcpy (msg + 4 + label_len + context_len, &l_be, 4);

  for (guint32 i = 1; i <= blocks; i++)
    {
      guint32 i_be = GUINT32_TO_BE (i);
      guint8 block[SHA256_DIGEST_LENGTH];
      gsize take;

      memcpy (msg, &i_be, 4);

      if (!hmac_sha256 (key, key_len, msg, msg_len, block))
        {
          memset (msg, 0, msg_len);
          return FALSE;
        }

      take = MIN (sizeof (block), want - produced);
      memcpy (out + produced, block, take);
      produced += take;
      OPENSSL_cleanse (block, sizeof (block));
    }

  memset (msg, 0, msg_len);
  return TRUE;
}

/* HMAC over "label\0" || extra */
static gboolean
hmac_labelled (const guint8 *key, const gchar *label,
               const guint8 *extra, gsize extra_len,
               guint8 *out)
{
  g_autofree guint8 *buf = NULL;
  gsize label_len = strlen (label) + 1;

  buf = g_malloc (label_len + extra_len);
  memcpy (buf, label, label_len);
  if (extra_len)
    memcpy (buf + label_len, extra, extra_len);

  gboolean ok = hmac_sha256 (key, SDCP_SECRET_LEN, buf, label_len + extra_len, out);
  memset (buf, 0, label_len + extra_len);
  return ok;
}

gboolean
vm_sdcp_build_connect (VerimarkSdcp *self, guint8 *out, gsize out_len, GError **error)
{
  g_autofree guint8 *pub = NULL;
  gsize pub_len;

  g_return_val_if_fail (self != NULL, FALSE);

  if (out_len != SDCP_CONNECT_MSG_LEN)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
                   "connect buffer must be %d bytes", SDCP_CONNECT_MSG_LEN);
      return FALSE;
    }

  g_clear_pointer (&self->ephemeral, EVP_PKEY_free);
  {
    EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_from_name (NULL, "EC", NULL);
    OSSL_PARAM kparams[2];
    gboolean ok = FALSE;

    kparams[0] = OSSL_PARAM_construct_utf8_string (OSSL_PKEY_PARAM_GROUP_NAME,
                                                   (char *) "prime256v1", 0);
    kparams[1] = OSSL_PARAM_construct_end ();

    if (kctx && EVP_PKEY_keygen_init (kctx) > 0 &&
        EVP_PKEY_CTX_set_params (kctx, kparams) > 0 &&
        EVP_PKEY_generate (kctx, &self->ephemeral) > 0)
      ok = TRUE;

    if (kctx)
      EVP_PKEY_CTX_free (kctx);

    if (!ok || !self->ephemeral)
      {
        g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                             "could not generate an ephemeral P-256 key");
        return FALSE;
      }
  }

  pub_len = EVP_PKEY_get1_encoded_public_key (self->ephemeral, &pub);
  if (pub_len != SDCP_PUBKEY_LEN || pub[0] != 0x04)
    {
      g_set_error (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                   "unexpected public key encoding (%" G_GSIZE_FORMAT " bytes)", pub_len);
      return FALSE;
    }

  vm_sdcp_random (self->host_random, sizeof (self->host_random));
  self->keys_derived = FALSE;
  self->established = FALSE;

  /* [u16 32][HostRandom][u16 65][PublicKeyHost] */
  out[0] = SDCP_RANDOM_LEN;
  out[1] = 0x00;
  memcpy (out + 2, self->host_random, SDCP_RANDOM_LEN);
  out[34] = SDCP_PUBKEY_LEN;
  out[35] = 0x00;
  memcpy (out + 36, pub, SDCP_PUBKEY_LEN);

  return TRUE;
}

static gboolean
derive_shared_secret (VerimarkSdcp *self,
                      const guint8 *peer_pub,
                      guint8       *out_secret,
                      gsize        *out_len,
                      GError      **error)
{
  EVP_PKEY_CTX *fctx = NULL, *dctx = NULL;
  EVP_PKEY *peer = NULL;
  OSSL_PARAM params[3];
  gboolean ok = FALSE;
  gsize secret_len = 0;

  fctx = EVP_PKEY_CTX_new_from_name (NULL, "EC", NULL);
  if (!fctx || EVP_PKEY_fromdata_init (fctx) <= 0)
    goto out;

  params[0] = OSSL_PARAM_construct_utf8_string (OSSL_PKEY_PARAM_GROUP_NAME,
                                                (char *) "prime256v1", 0);
  params[1] = OSSL_PARAM_construct_octet_string (OSSL_PKEY_PARAM_PUB_KEY,
                                                 (void *) peer_pub, SDCP_PUBKEY_LEN);
  params[2] = OSSL_PARAM_construct_end ();

  if (EVP_PKEY_fromdata (fctx, &peer, EVP_PKEY_PUBLIC_KEY, params) <= 0 || !peer)
    goto out;

  dctx = EVP_PKEY_CTX_new (self->ephemeral, NULL);
  if (!dctx || EVP_PKEY_derive_init (dctx) <= 0)
    goto out;
  if (EVP_PKEY_derive_set_peer (dctx, peer) <= 0)
    goto out;
  if (EVP_PKEY_derive (dctx, NULL, &secret_len) <= 0 || secret_len > *out_len)
    goto out;
  if (EVP_PKEY_derive (dctx, out_secret, &secret_len) <= 0)
    goto out;

  *out_len = secret_len;
  ok = TRUE;

out:
  if (!ok)
    g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                         "ECDH key agreement failed");
  if (peer)
    EVP_PKEY_free (peer);
  if (dctx)
    EVP_PKEY_CTX_free (dctx);
  if (fctx)
    EVP_PKEY_CTX_free (fctx);
  return ok;
}

gboolean
vm_sdcp_handle_connect_response (VerimarkSdcp *self,
                                 const guint8 *resp,
                                 gsize         resp_len,
                                 GError      **error)
{
  gsize off = 0;
  guint16 n_random, n_claim, n_mac;
  const guint8 *claim, *claim_mac, *fw_pub;
  guint8 shared[128];
  gsize shared_len = sizeof (shared);
  guint8 master[SDCP_SECRET_LEN];
  guint8 app_keys[SDCP_SECRET_LEN * 2];
  guint8 context[SDCP_RANDOM_LEN * 2];
  guint8 claim_hash[SHA256_DIGEST_LENGTH];
  guint8 expected[SDCP_MAC_LEN];
  gboolean ok = FALSE;

  g_return_val_if_fail (self != NULL && self->ephemeral != NULL, FALSE);

  /* [u16][DeviceRandom][u16][claim][u16][ClaimMAC][padding] */
  if (resp_len < 6 + SDCP_RANDOM_LEN + CLAIM_TAIL_LEN + SDCP_MAC_LEN)
    goto malformed;

  n_random = resp[off] | (resp[off + 1] << 8);
  off += 2;
  if (n_random != SDCP_RANDOM_LEN || off + n_random > resp_len)
    goto malformed;
  memcpy (self->device_random, resp + off, SDCP_RANDOM_LEN);
  off += n_random;

  if (off + 2 > resp_len)
    goto malformed;
  n_claim = resp[off] | (resp[off + 1] << 8);
  off += 2;
  if (n_claim < CLAIM_TAIL_LEN || off + n_claim > resp_len)
    goto malformed;
  claim = resp + off;
  off += n_claim;

  if (off + 2 > resp_len)
    goto malformed;
  n_mac = resp[off] | (resp[off + 1] << 8);
  off += 2;
  if (n_mac != SDCP_MAC_LEN || off + n_mac > resp_len)
    goto malformed;
  claim_mac = resp + off;

  /*
   * ECDH is against the FIRMWARE public key, not the device key. The device
   * key signs the firmware key; the firmware key is the key-agreement key.
   */
  fw_pub = claim + n_claim - CLAIM_FW_PUBKEY_OFF_FROM_END;
  if (fw_pub[0] != 0x04)
    goto malformed;

  if (!derive_shared_secret (self, fw_pub, shared, &shared_len, error))
    return FALSE;

  memcpy (context, self->host_random, SDCP_RANDOM_LEN);
  memcpy (context + SDCP_RANDOM_LEN, self->device_random, SDCP_RANDOM_LEN);

  if (!sp800108_kdf (shared, shared_len, "master secret",
                     context, sizeof (context), 256, master, sizeof (master)))
    goto crypto_failed;

  if (!sp800108_kdf (master, sizeof (master), "application keys",
                     NULL, 0, 512, app_keys, sizeof (app_keys)))
    goto crypto_failed;

  memcpy (self->mac_secret, app_keys, SDCP_SECRET_LEN);
  memcpy (self->sym_key, app_keys + SDCP_SECRET_LEN, SDCP_SECRET_LEN);

  /* ClaimMAC = HMAC(MAC_secret, "connect\0" || SHA256(claim)) */
  SHA256 (claim, n_claim, claim_hash);
  if (!hmac_labelled (self->mac_secret, "connect",
                      claim_hash, sizeof (claim_hash), expected))
    goto crypto_failed;

  if (CRYPTO_memcmp (expected, claim_mac, SDCP_MAC_LEN) != 0)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                           "SDCP ClaimMAC mismatch — key agreement did not "
                           "produce the key the device is using");
      goto out;
    }

  self->keys_derived = TRUE;
  ok = TRUE;
  goto out;

malformed:
  g_set_error (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
               "malformed SDCP connect response (%" G_GSIZE_FORMAT " bytes)", resp_len);
  goto out;

crypto_failed:
  g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                       "SDCP key derivation failed");

out:
  OPENSSL_cleanse (shared, sizeof (shared));
  OPENSSL_cleanse (master, sizeof (master));
  OPENSSL_cleanse (app_keys, sizeof (app_keys));
  return ok;
}

gboolean
vm_sdcp_build_reconnect (VerimarkSdcp *self, guint8 *out, gsize out_len, GError **error)
{
  g_return_val_if_fail (self != NULL, FALSE);

  if (out_len != SDCP_RECONNECT_MSG_LEN || !self->keys_derived)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_ARGUMENT,
                           "reconnect requested before keys were derived");
      return FALSE;
    }

  vm_sdcp_random (self->reconnect_random, sizeof (self->reconnect_random));
  out[0] = SDCP_RANDOM_LEN;
  out[1] = 0x00;
  memcpy (out + 2, self->reconnect_random, SDCP_RANDOM_LEN);
  return TRUE;
}

gboolean
vm_sdcp_handle_reconnect_response (VerimarkSdcp *self,
                                   const guint8 *resp,
                                   gsize         resp_len,
                                   GError      **error)
{
  guint8 expected[SDCP_MAC_LEN];
  guint16 n;

  g_return_val_if_fail (self != NULL, FALSE);

  if (resp_len < 2 + SDCP_MAC_LEN)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                           "short SDCP reconnect response");
      return FALSE;
    }

  n = resp[0] | (resp[1] << 8);
  if (n != SDCP_MAC_LEN)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_INVALID_DATA,
                           "malformed SDCP reconnect response");
      return FALSE;
    }

  /* ReconnectionMAC = HMAC(MAC_secret, "reconnect\0" || HostRandom) */
  if (!hmac_labelled (self->mac_secret, "reconnect",
                      self->reconnect_random, SDCP_RANDOM_LEN, expected))
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED, "HMAC failed");
      return FALSE;
    }

  if (CRYPTO_memcmp (expected, resp + 2, SDCP_MAC_LEN) != 0)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                           "SDCP ReconnectionMAC mismatch");
      return FALSE;
    }

  self->established = TRUE;
  return TRUE;
}

gboolean
vm_sdcp_enrollment_id (VerimarkSdcp *self,
                       const guint8 *nonce,
                       guint8       *out_id,
                       GError      **error)
{
  g_return_val_if_fail (self != NULL, FALSE);

  if (!self->established)
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED,
                           "no SDCP session; the device will reject the commit");
      return FALSE;
    }

  /* enrollment_id = HMAC(MAC_secret, "enroll\0" || nonce) */
  if (!hmac_labelled (self->mac_secret, "enroll", nonce, SDCP_RANDOM_LEN, out_id))
    {
      g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_FAILED, "HMAC failed");
      return FALSE;
    }

  return TRUE;
}

gboolean
vm_sdcp_verify_identify_mac (VerimarkSdcp *self,
                             const guint8 *nonce,
                             const guint8 *enrollment_id,
                             const guint8 *mac)
{
  guint8 expected[SDCP_MAC_LEN];
  guint8 buf[SDCP_RANDOM_LEN + SDCP_SECRET_LEN];

  g_return_val_if_fail (self != NULL, FALSE);

  if (!self->established)
    return FALSE;

  /* AuthenticationMAC = HMAC(MAC_secret, "identify\0" || nonce || enrollment_id) */
  memcpy (buf, nonce, SDCP_RANDOM_LEN);
  memcpy (buf + SDCP_RANDOM_LEN, enrollment_id, SDCP_SECRET_LEN);

  if (!hmac_labelled (self->mac_secret, "identify", buf, sizeof (buf), expected))
    return FALSE;

  return CRYPTO_memcmp (expected, mac, SDCP_MAC_LEN) == 0;
}

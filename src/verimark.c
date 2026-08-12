/*
 * Kensington VeriMark Desktop 2.0 fingerprint driver
 * Copyright (C) 2026 Parth
 *
 * Structure follows libfprint's realtek driver (LGPL-2.1+), which speaks the
 * same bulk transport. The differences from it are all firmware-specific and
 * were established from a USB capture of the Windows driver:
 *   - the template table stride is 52 bytes, not 35
 *   - start/poll capture carry the purpose in param
 *   - the commit opcode is 85 0a / param 0xf5 / 49 bytes, not 85 21
 *   - enrollment is gated behind Microsoft SDCP
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 */

#include "verimark.h"
#include "verimark-sdcp.h"

#include <string.h>
#include <openssl/sha.h>

#define FP_COMPONENT "verimark"

/* how long to wait between finger-presence polls */
#define POLL_INTERVAL_MS 80

struct _FpDeviceVerimark
{
  FpDevice        parent;

  FpiSsm         *task_ssm;
  FpiSsm         *cmd_ssm;

  /* current command */
  FpiUsbTransfer *cmd_transfer;
  FpiUsbTransfer *data_transfer;
  gint            cmd_type;
  gsize           expect_len;
  guint8         *read_data;
  gboolean        ignore_status;
  gboolean        cmd_cancellable;

  VerimarkSdcp   *sdcp;

  /* device properties */
  gint            slot_count;

  /* per-operation state */
  VerimarkPurpose purpose;
  gint            enroll_stage;
  gint            max_enroll_stage;
  guint8          enrollment_id[SDCP_SECRET_LEN];
  guint8          identify_nonce[SDCP_RANDOM_LEN];
  guint8          template_table[VM_TEMPLATE_TABLE_LEN];
  gint            delete_slot;
};

G_DEFINE_TYPE (FpDeviceVerimark, fp_device_verimark, FP_TYPE_DEVICE)

static const FpIdEntry id_table[] = {
  { .vid = VERIMARK_VID, .pid = VERIMARK_PID, },
  { .vid = 0, .pid = 0, .driver_data = 0 },
};

typedef void (*VmCmdCb) (FpDeviceVerimark *self, guint8 *data, GError *error);

typedef struct
{
  VmCmdCb callback;
} VmCmdData;

enum {
  VM_CMD_STATE_SEND = 0,
  VM_CMD_STATE_DATA,
  VM_CMD_STATE_STATUS,
  VM_CMD_STATE_NUM,
};

/* ------------------------------------------------------------------------ */
/* print helpers                                                             */
/* ------------------------------------------------------------------------ */

/*
 * A print carries SHA-256(enrollment_id) — the same value the chip keeps in
 * its template table. The raw enrollment_id only ever exists transiently: the
 * device hands it back on a match, we verify its MAC, hash it, and compare.
 */
static FpPrint *
vm_print_new (FpDeviceVerimark *self, guint8 subfactor, const guint8 *id_hash)
{
  FpPrint *print = fp_print_new (FP_DEVICE (self));
  GVariant *data, *uid;

  uid = g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE, id_hash, VM_REC_ID_LEN, 1);
  data = g_variant_new ("(y@ay)", subfactor, uid);

  fpi_print_set_type (print, FPI_PRINT_RAW);
  fpi_print_set_device_stored (print, TRUE);
  g_object_set (print, "fpi-data", data, NULL);

  return print;
}

static gboolean
vm_print_get_id (FpPrint *print, guint8 *out_hash, guint8 *out_subfactor)
{
  g_autoptr(GVariant) data = NULL;
  g_autoptr(GVariant) uid = NULL;
  const guint8 *raw;
  gsize len = 0;
  guint8 subfactor = 0;

  if (!print)
    return FALSE;

  g_object_get (print, "fpi-data", &data, NULL);
  if (!data || !g_variant_check_format_string (data, "(y@ay)", FALSE))
    return FALSE;

  g_variant_get (data, "(y@ay)", &subfactor, &uid);
  raw = g_variant_get_fixed_array (uid, &len, 1);
  if (!raw || len != VM_REC_ID_LEN)
    return FALSE;

  memcpy (out_hash, raw, VM_REC_ID_LEN);
  if (out_subfactor)
    *out_subfactor = subfactor;

  return TRUE;
}

/* ------------------------------------------------------------------------ */
/* command engine                                                            */
/* ------------------------------------------------------------------------ */

static void
vm_cmd_receive_cb (FpiUsbTransfer *transfer,
                   FpDevice       *device,
                   gpointer        user_data,
                   GError         *error)
{
  FpDeviceVerimark *self = FP_DEVICE_VERIMARK (device);
  gint state;

  if (error)
    {
      fpi_ssm_mark_failed (transfer->ssm, error);
      return;
    }

  state = fpi_ssm_get_cur_state (transfer->ssm);

  /* the device occasionally emits a zero-length packet; just read again */
  if (transfer->actual_length == 0)
    {
      fpi_ssm_jump_to_state (transfer->ssm, state);
      return;
    }

  if (state == VM_CMD_STATE_DATA)
    {
      if ((gsize) transfer->actual_length < self->expect_len)
        {
          fpi_ssm_mark_failed (transfer->ssm,
                               fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                         "short read: wanted %" G_GSIZE_FORMAT
                                                         ", got %d", self->expect_len,
                                                         (int) transfer->actual_length));
          return;
        }

      g_clear_pointer (&self->read_data, g_free);
      self->read_data = g_memdup2 (transfer->buffer, self->expect_len);
      fpi_ssm_next_state (transfer->ssm);
      return;
    }

  /* status packet: [status u8][err i32le] */
  if (transfer->actual_length < STATUS_LEN)
    {
      fpi_ssm_mark_failed (transfer->ssm,
                           fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                     "truncated status packet"));
      return;
    }

  if (transfer->buffer[0] != 0 && !self->ignore_status)
    {
      gint32 err_code;

      memcpy (&err_code, transfer->buffer + 1, sizeof (err_code));
      err_code = GINT32_FROM_LE (err_code);

      fpi_ssm_mark_failed (transfer->ssm,
                           fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                     "device rejected command "
                                                     "(status %u, error %d)",
                                                     transfer->buffer[0], err_code));
      return;
    }

  fpi_ssm_mark_completed (transfer->ssm);
}

static void
vm_cmd_run_state (FpiSsm *ssm, FpDevice *dev)
{
  FpDeviceVerimark *self = FP_DEVICE_VERIMARK (dev);
  FpiUsbTransfer *transfer = NULL;

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case VM_CMD_STATE_SEND:
      self->cmd_transfer->ssm = ssm;
      fpi_usb_transfer_submit (g_steal_pointer (&self->cmd_transfer),
                               CMD_TIMEOUT, NULL,
                               fpi_ssm_usb_transfer_cb, NULL);
      break;

    case VM_CMD_STATE_DATA:
      if (self->cmd_type == VM_CMD_NONE)
        {
          fpi_ssm_jump_to_state (ssm, VM_CMD_STATE_STATUS);
          break;
        }

      if (self->cmd_type == VM_CMD_WRITE)
        {
          if (self->data_transfer)
            {
              self->data_transfer->ssm = ssm;
              fpi_usb_transfer_submit (g_steal_pointer (&self->data_transfer),
                                       DATA_TIMEOUT, NULL,
                                       fpi_ssm_usb_transfer_cb, NULL);
            }
          else
            {
              fpi_ssm_next_state (ssm);
            }
          break;
        }

      /* VM_CMD_READ */
      transfer = fpi_usb_transfer_new (dev);
      transfer->ssm = ssm;
      fpi_usb_transfer_fill_bulk (transfer, EP_IN, EP_IN_MAX_BUF_SIZE);
      fpi_usb_transfer_submit (transfer,
                               self->cmd_cancellable ? 0 : DATA_TIMEOUT,
                               self->cmd_cancellable ? fpi_device_get_cancellable (dev) : NULL,
                               vm_cmd_receive_cb, NULL);
      break;

    case VM_CMD_STATE_STATUS:
      transfer = fpi_usb_transfer_new (dev);
      transfer->ssm = ssm;
      fpi_usb_transfer_fill_bulk (transfer, EP_IN, EP_IN_MAX_BUF_SIZE);
      fpi_usb_transfer_submit (transfer, STATUS_TIMEOUT, NULL,
                               vm_cmd_receive_cb, NULL);
      break;

    default:
      g_assert_not_reached ();
    }
}

static void
vm_cmd_ssm_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpDeviceVerimark *self = FP_DEVICE_VERIMARK (dev);
  VmCmdData *data = fpi_ssm_get_data (ssm);
  g_autofree guint8 *payload = NULL;

  /* clear before invoking the callback: it will often start the next command */
  if (self->cmd_ssm == ssm)
    self->cmd_ssm = NULL;

  payload = g_steal_pointer (&self->read_data);

  if (data && data->callback)
    data->callback (self, error ? NULL : payload, error);
  else if (error)
    g_error_free (error);
}

static void
vm_cmd (FpDeviceVerimark *self,
        guint8            cmd0,
        guint8            cmd1,
        const guint8     *param,
        guint16           data_len,
        const guint8     *payload,
        gsize             payload_len,
        gboolean          ignore_status,
        gboolean          cancellable,
        VmCmdCb           callback)
{
  FpDevice *dev = FP_DEVICE (self);
  VmCmdData *data;
  guint8 *pkt;

  pkt = g_malloc0 (CMD_PKT_LEN);
  pkt[0] = cmd0;
  pkt[1] = cmd1;
  if (param)
    memcpy (pkt + 2, param, 4);
  /* addr (bytes 6..9) is always zero on this device */
  pkt[10] = data_len & 0xFF;
  pkt[11] = (data_len >> 8) & 0xFF;

  self->cmd_type = VM_CMD_TYPE (cmd0);
  self->expect_len = data_len;
  self->ignore_status = ignore_status;
  self->cmd_cancellable = cancellable;

  g_clear_pointer (&self->cmd_transfer, fpi_usb_transfer_unref);
  self->cmd_transfer = fpi_usb_transfer_new (dev);
  fpi_usb_transfer_fill_bulk_full (self->cmd_transfer, EP_OUT, pkt,
                                   CMD_PKT_LEN, g_free);

  g_clear_pointer (&self->data_transfer, fpi_usb_transfer_unref);
  if (self->cmd_type == VM_CMD_WRITE && payload && payload_len > 0)
    {
      self->data_transfer = fpi_usb_transfer_new (dev);
      fpi_usb_transfer_fill_bulk_full (self->data_transfer, EP_OUT,
                                       g_memdup2 (payload, payload_len),
                                       payload_len, g_free);
    }

  data = g_new0 (VmCmdData, 1);
  data->callback = callback;

  self->cmd_ssm = fpi_ssm_new (dev, vm_cmd_run_state, VM_CMD_STATE_NUM);
  fpi_ssm_set_data (self->cmd_ssm, data, g_free);
  fpi_ssm_start (self->cmd_ssm, vm_cmd_ssm_done);
}

/* generic: advance the task SSM, or fail it */
static void
vm_generic_cb (FpDeviceVerimark *self, guint8 *data, GError *error)
{
  if (error)
    {
      fpi_ssm_mark_failed (self->task_ssm, error);
      return;
    }
  fpi_ssm_next_state (self->task_ssm);
}

/* ------------------------------------------------------------------------ */
/* init / open                                                               */
/* ------------------------------------------------------------------------ */

enum {
  VM_INIT_GET_INFO = 0,
  VM_INIT_SELECT_OS,
  VM_INIT_GET_ENROLL_NUM,
  VM_INIT_SDCP_CONNECT,
  VM_INIT_SDCP_CONNECT_RESP,
  VM_INIT_SDCP_RECONNECT,
  VM_INIT_SDCP_RECONNECT_RESP,
  VM_INIT_NUM_STATES,
};

static void
vm_get_enroll_num_cb (FpDeviceVerimark *self, guint8 *data, GError *error)
{
  if (error)
    {
      fpi_ssm_mark_failed (self->task_ssm, error);
      return;
    }

  /* reply is [?][capacity] */
  self->slot_count = MIN (data[1], VM_MAX_SLOTS);
  if (self->slot_count <= 0)
    self->slot_count = VM_MAX_SLOTS;

  fp_dbg ("device reports %d template slots", self->slot_count);
  fpi_ssm_next_state (self->task_ssm);
}

static void
vm_sdcp_connect_resp_cb (FpDeviceVerimark *self, guint8 *data, GError *error)
{
  g_autoptr(GError) local = NULL;

  if (error)
    {
      fpi_ssm_mark_failed (self->task_ssm, error);
      return;
    }

  if (!vm_sdcp_handle_connect_response (self->sdcp, data,
                                        SDCP_CONNECT_RESP_LEN, &local))
    {
      fpi_ssm_mark_failed (self->task_ssm,
                           fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                     "SDCP connect failed: %s",
                                                     local->message));
      return;
    }

  fp_dbg ("SDCP claim verified");
  fpi_ssm_next_state (self->task_ssm);
}

static void
vm_sdcp_reconnect_resp_cb (FpDeviceVerimark *self, guint8 *data, GError *error)
{
  g_autoptr(GError) local = NULL;

  if (error)
    {
      fpi_ssm_mark_failed (self->task_ssm, error);
      return;
    }

  if (!vm_sdcp_handle_reconnect_response (self->sdcp, data,
                                          SDCP_RECONNECT_RESP_LEN, &local))
    {
      fpi_ssm_mark_failed (self->task_ssm,
                           fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                     "SDCP reconnect failed: %s",
                                                     local->message));
      return;
    }

  fp_dbg ("SDCP session established");
  fpi_ssm_next_state (self->task_ssm);
}

static void
vm_init_run_state (FpiSsm *ssm, FpDevice *dev)
{
  FpDeviceVerimark *self = FP_DEVICE_VERIMARK (dev);
  g_autoptr(GError) error = NULL;
  guint8 param[4] = { 0 };
  guint8 buf[SDCP_CONNECT_MSG_LEN];

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case VM_INIT_GET_INFO:
      param[0] = 0x0D;
      vm_cmd (self, VM_GET_PROP, param, 8, NULL, 0, FALSE, FALSE, vm_generic_cb);
      break;

    case VM_INIT_SELECT_OS:
      /* Windows selects 0; the value turns out not to matter, but match it */
      param[0] = 0x00;
      vm_cmd (self, VM_SELECT_OS, param, 0, NULL, 0, FALSE, FALSE, vm_generic_cb);
      break;

    case VM_INIT_GET_ENROLL_NUM:
      vm_cmd (self, VM_GET_ENROLL_NUM, NULL, 2, NULL, 0, FALSE, FALSE,
              vm_get_enroll_num_cb);
      break;

    case VM_INIT_SDCP_CONNECT:
      if (!vm_sdcp_build_connect (self->sdcp, buf, sizeof (buf), &error))
        {
          fpi_ssm_mark_failed (ssm, g_steal_pointer (&error));
          return;
        }
      vm_cmd (self, VM_SDCP_CONNECT, NULL, sizeof (buf), buf, sizeof (buf),
              FALSE, FALSE, vm_generic_cb);
      break;

    case VM_INIT_SDCP_CONNECT_RESP:
      vm_cmd (self, VM_SDCP_CONNECT_RESP, NULL, SDCP_CONNECT_RESP_LEN,
              NULL, 0, FALSE, FALSE, vm_sdcp_connect_resp_cb);
      break;

    case VM_INIT_SDCP_RECONNECT:
      if (!vm_sdcp_build_reconnect (self->sdcp, buf, SDCP_RECONNECT_MSG_LEN, &error))
        {
          fpi_ssm_mark_failed (ssm, g_steal_pointer (&error));
          return;
        }
      vm_cmd (self, VM_SDCP_RECONNECT, NULL, SDCP_RECONNECT_MSG_LEN,
              buf, SDCP_RECONNECT_MSG_LEN, FALSE, FALSE, vm_generic_cb);
      break;

    case VM_INIT_SDCP_RECONNECT_RESP:
      vm_cmd (self, VM_SDCP_RECONNECT_RESP, NULL, SDCP_RECONNECT_RESP_LEN,
              NULL, 0, FALSE, FALSE, vm_sdcp_reconnect_resp_cb);
      break;

    default:
      g_assert_not_reached ();
    }
}

static void
vm_init_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpDeviceVerimark *self = FP_DEVICE_VERIMARK (dev);

  self->task_ssm = NULL;
  fpi_device_open_complete (dev, error);
}

static void
vm_open (FpDevice *device)
{
  FpDeviceVerimark *self = FP_DEVICE_VERIMARK (device);
  g_autoptr(GError) error = NULL;

  /* libfprint has already opened the USB device; we only claim the interface */
  if (!g_usb_device_claim_interface (fpi_device_get_usb_device (device), 0, 0, &error))
    {
      fpi_device_open_complete (device, g_steal_pointer (&error));
      return;
    }

  g_clear_pointer (&self->sdcp, vm_sdcp_free);
  self->sdcp = vm_sdcp_new ();

  self->task_ssm = fpi_ssm_new (device, vm_init_run_state, VM_INIT_NUM_STATES);
  fpi_ssm_start (self->task_ssm, vm_init_done);
}

static void
vm_close (FpDevice *device)
{
  FpDeviceVerimark *self = FP_DEVICE_VERIMARK (device);
  GUsbDevice *usb_dev = fpi_device_get_usb_device (device);
  g_autoptr(GError) error = NULL;

  g_clear_pointer (&self->sdcp, vm_sdcp_free);
  g_clear_pointer (&self->read_data, g_free);
  g_clear_pointer (&self->cmd_transfer, fpi_usb_transfer_unref);
  g_clear_pointer (&self->data_transfer, fpi_usb_transfer_unref);

  g_usb_device_release_interface (usb_dev, 0, 0, &error);

  fpi_device_close_complete (device, g_steal_pointer (&error));
}

/* ------------------------------------------------------------------------ */
/* capture helpers shared by enroll and verify                               */
/* ------------------------------------------------------------------------ */

static void
vm_start_capture (FpDeviceVerimark *self, VerimarkPurpose purpose, VmCmdCb cb)
{
  guint8 param[4] = { purpose, 0x02, 0x00, 0x00 };

  fpi_device_report_finger_status_changes (FP_DEVICE (self),
                                           FP_FINGER_STATUS_NEEDED,
                                           FP_FINGER_STATUS_NONE);
  vm_cmd (self, VM_START_CAPTURE, param, 0, NULL, 0, FALSE, FALSE, cb);
}

static void
vm_poll_capture (FpDeviceVerimark *self, VerimarkPurpose purpose, VmCmdCb cb)
{
  guint8 param[4] = { purpose, 0x02, 0x00, 0x00 };

  vm_cmd (self, VM_POLL_CAPTURE, param, 5, NULL, 0, FALSE, TRUE, cb);
}

static void
vm_accept_sample (FpDeviceVerimark *self, VerimarkPurpose purpose, VmCmdCb cb)
{
  guint8 param[4] = { purpose, 0x00, 0x00, 0x00 };

  /* the sample reply carries its verdict in the payload; a non-zero status
   * accompanies perfectly normal outcomes, so do not treat it as fatal */
  vm_cmd (self, VM_ACCEPT_SAMPLE, param, 9, NULL, 0, TRUE, FALSE, cb);
}

/*
 * Poll result handling shared by both flows: returns TRUE when a finger has
 * been captured and the caller should advance.
 */
static gboolean
vm_poll_done (FpDeviceVerimark *self, guint8 *data, GError *error, gint poll_state)
{
  GCancellable *cancellable;

  if (error)
    {
      fpi_ssm_mark_failed (self->task_ssm, error);
      return FALSE;
    }

  cancellable = fpi_device_get_cancellable (FP_DEVICE (self));
  if (cancellable && g_cancellable_is_cancelled (cancellable))
    {
      fpi_ssm_mark_failed (self->task_ssm,
                           g_error_new_literal (G_IO_ERROR, G_IO_ERROR_CANCELLED,
                                                "cancelled"));
      return FALSE;
    }

  if (data[0] == VM_CAPTURE_DONE)
    {
      fpi_device_report_finger_status_changes (FP_DEVICE (self),
                                               FP_FINGER_STATUS_PRESENT,
                                               FP_FINGER_STATUS_NEEDED);
      return TRUE;
    }

  /* no finger yet — poll again shortly rather than spinning */
  fpi_ssm_jump_to_state_delayed (self->task_ssm, poll_state, POLL_INTERVAL_MS);
  return FALSE;
}

/* ------------------------------------------------------------------------ */
/* enroll                                                                    */
/* ------------------------------------------------------------------------ */

enum {
  VM_ENROLL_NONCE_STATE = 0,
  VM_ENROLL_CAPTURE,
  VM_ENROLL_POLL,
  VM_ENROLL_ACCEPT,
  VM_ENROLL_CHECK_DUP,
  VM_ENROLL_COMMIT_STATE,
  VM_ENROLL_NUM_STATES,
};

static void
vm_enroll_nonce_cb (FpDeviceVerimark *self, guint8 *data, GError *error)
{
  g_autoptr(GError) local = NULL;

  if (error)
    {
      fpi_ssm_mark_failed (self->task_ssm, error);
      return;
    }

  if (!vm_sdcp_enrollment_id (self->sdcp, data, self->enrollment_id, &local))
    {
      fpi_ssm_mark_failed (self->task_ssm,
                           fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                     "%s", local->message));
      return;
    }

  fpi_ssm_next_state (self->task_ssm);
}

static void
vm_enroll_poll_cb (FpDeviceVerimark *self, guint8 *data, GError *error)
{
  if (vm_poll_done (self, data, error, VM_ENROLL_POLL))
    fpi_ssm_next_state (self->task_ssm);
}

static void
vm_enroll_accept_cb (FpDeviceVerimark *self, guint8 *data, GError *error)
{
  guint8 verdict;

  fpi_device_report_finger_status_changes (FP_DEVICE (self),
                                           FP_FINGER_STATUS_NONE,
                                           FP_FINGER_STATUS_PRESENT);

  if (error)
    {
      fpi_ssm_mark_failed (self->task_ssm, error);
      return;
    }

  verdict = data[0];

  if (verdict == VM_CMD_ERR)
    {
      fpi_ssm_mark_failed (self->task_ssm,
                           fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                     "sensor reported a command error"));
      return;
    }

  if (verdict == VM_SUCCESS)
    {
      self->enroll_stage++;
      fpi_device_enroll_progress (FP_DEVICE (self), self->enroll_stage, NULL, NULL);
    }
  else
    {
      /* a poor sample: tell the UI to retry, do not count it */
      fpi_device_enroll_progress (FP_DEVICE (self), self->enroll_stage, NULL,
                                  fpi_device_retry_new (FP_DEVICE_RETRY_GENERAL));
    }

  if (self->enroll_stage < self->max_enroll_stage)
    fpi_ssm_jump_to_state (self->task_ssm, VM_ENROLL_CAPTURE);
  else
    fpi_ssm_next_state (self->task_ssm);
}

static void
vm_enroll_check_dup_cb (FpDeviceVerimark *self, guint8 *data, GError *error)
{
  if (error)
    {
      fpi_ssm_mark_failed (self->task_ssm, error);
      return;
    }

  /*
   * 0x0b (MATCH_FAIL) is the good case: no existing template matches. A 0x00
   * means this finger is already enrolled, which the firmware will refuse to
   * commit anyway, so report it plainly.
   */
  if (data[0] == VM_SUCCESS)
    {
      fpi_ssm_mark_failed (self->task_ssm,
                           fpi_device_error_new_msg (FP_DEVICE_ERROR_DATA_DUPLICATE,
                                                     "this finger is already enrolled "
                                                     "on the sensor"));
      return;
    }

  fpi_ssm_next_state (self->task_ssm);
}

static void
vm_enroll_commit_cb (FpDeviceVerimark *self, guint8 *data, GError *error)
{
  if (error)
    {
      fpi_ssm_mark_failed (self->task_ssm, error);
      return;
    }

  fpi_ssm_mark_completed (self->task_ssm);
}

static void
vm_enroll_run_state (FpiSsm *ssm, FpDevice *dev)
{
  FpDeviceVerimark *self = FP_DEVICE_VERIMARK (dev);
  guint8 param[4] = { 0 };
  guint8 payload[VM_COMMIT_PAYLOAD_LEN];

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case VM_ENROLL_NONCE_STATE:
      param[0] = VM_PURPOSE_ENROLL;
      vm_cmd (self, VM_ENROLL_NONCE, param, SDCP_RANDOM_LEN, NULL, 0,
              FALSE, FALSE, vm_enroll_nonce_cb);
      break;

    case VM_ENROLL_CAPTURE:
      vm_start_capture (self, VM_PURPOSE_ENROLL, vm_generic_cb);
      break;

    case VM_ENROLL_POLL:
      vm_poll_capture (self, VM_PURPOSE_ENROLL, vm_enroll_poll_cb);
      break;

    case VM_ENROLL_ACCEPT:
      vm_accept_sample (self, VM_PURPOSE_ENROLL, vm_enroll_accept_cb);
      break;

    case VM_ENROLL_CHECK_DUP:
      param[0] = 0x01;
      /* returns 0x0b with a non-zero status when there is no duplicate */
      vm_cmd (self, VM_CHECK_DUPLICATE, param, 34, NULL, 0, TRUE, FALSE,
              vm_enroll_check_dup_cb);
      break;

    case VM_ENROLL_COMMIT_STATE:
      memset (payload, 0, sizeof (payload));
      memcpy (payload, self->enrollment_id, SDCP_SECRET_LEN);
      /* the remaining 17 bytes are opaque host metadata; Windows stores its
       * own there and the device keeps whatever we send verbatim */
      param[0] = VM_SUBFACTOR;
      vm_cmd (self, VM_ENROLL_COMMIT, param, VM_COMMIT_PAYLOAD_LEN,
              payload, sizeof (payload), FALSE, FALSE, vm_enroll_commit_cb);
      break;

    default:
      g_assert_not_reached ();
    }
}

static void
vm_enroll_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpDeviceVerimark *self = FP_DEVICE_VERIMARK (dev);
  FpPrint *print = NULL;
  guint8 id_hash[SHA256_DIGEST_LENGTH];

  self->task_ssm = NULL;

  if (error)
    {
      fpi_device_enroll_complete (dev, NULL, error);
      return;
    }

  fpi_device_get_enroll_data (dev, &print);

  /* the chip stores SHA-256 of the enrollment id; mirror that in the print */
  SHA256 (self->enrollment_id, SDCP_SECRET_LEN, id_hash);

  {
    GVariant *uid = g_variant_new_fixed_array (G_VARIANT_TYPE_BYTE, id_hash,
                                               VM_REC_ID_LEN, 1);
    GVariant *data = g_variant_new ("(y@ay)", (guint8) VM_SUBFACTOR, uid);

    fpi_print_set_type (print, FPI_PRINT_RAW);
    fpi_print_set_device_stored (print, TRUE);
    g_object_set (print, "fpi-data", data, NULL);
  }

  fpi_device_enroll_complete (dev, g_object_ref (print), NULL);
}

static void
vm_enroll (FpDevice *device)
{
  FpDeviceVerimark *self = FP_DEVICE_VERIMARK (device);

  self->enroll_stage = 0;
  self->max_enroll_stage = VM_ENROLL_STAGES;
  self->purpose = VM_PURPOSE_ENROLL;

  self->task_ssm = fpi_ssm_new (device, vm_enroll_run_state, VM_ENROLL_NUM_STATES);
  fpi_ssm_start (self->task_ssm, vm_enroll_done);
}

/* ------------------------------------------------------------------------ */
/* verify / identify                                                         */
/* ------------------------------------------------------------------------ */

enum {
  VM_VERIFY_CAPTURE = 0,
  VM_VERIFY_POLL,
  VM_VERIFY_ACCEPT,
  VM_VERIFY_NONCE,
  VM_VERIFY_IDENTIFY_STATE,
  VM_VERIFY_NUM_STATES,
};

static void
vm_verify_poll_cb (FpDeviceVerimark *self, guint8 *data, GError *error)
{
  if (vm_poll_done (self, data, error, VM_VERIFY_POLL))
    fpi_ssm_next_state (self->task_ssm);
}

static void
vm_verify_accept_cb (FpDeviceVerimark *self, guint8 *data, GError *error)
{
  fpi_device_report_finger_status_changes (FP_DEVICE (self),
                                           FP_FINGER_STATUS_NONE,
                                           FP_FINGER_STATUS_PRESENT);

  if (error)
    {
      fpi_ssm_mark_failed (self->task_ssm, error);
      return;
    }

  if (data[0] == VM_CMD_ERR)
    {
      fpi_ssm_mark_failed (self->task_ssm,
                           fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                     "sensor reported a command error"));
      return;
    }

  fpi_ssm_next_state (self->task_ssm);
}

static void
vm_report_no_match (FpDeviceVerimark *self)
{
  FpDevice *dev = FP_DEVICE (self);

  if (fpi_device_get_current_action (dev) == FPI_DEVICE_ACTION_VERIFY)
    fpi_device_verify_report (dev, FPI_MATCH_FAIL, NULL, NULL);
  else
    fpi_device_identify_report (dev, NULL, NULL, NULL);

  fpi_ssm_mark_completed (self->task_ssm);
}

static void
vm_identify_cb (FpDeviceVerimark *self, guint8 *data, GError *error)
{
  FpDevice *dev = FP_DEVICE (self);
  g_autoptr(FpPrint) match = NULL;
  guint8 id_hash[SHA256_DIGEST_LENGTH];
  guint8 subfactor;
  const guint8 *enrollment_id;
  const guint8 *mac;

  if (error)
    {
      fpi_ssm_mark_failed (self->task_ssm, error);
      return;
    }

  /* [status][subfactor][enrollment_id 32][AuthenticationMAC 32][8] */
  if (data[0] != VM_SUCCESS)
    {
      vm_report_no_match (self);
      return;
    }

  subfactor = data[1];
  enrollment_id = data + VM_IDENT_ID_OFF;
  mac = data + VM_IDENT_MAC_OFF;

  /*
   * The whole point of SDCP: do not believe a match unless the sensor can
   * prove it with a MAC over our nonce.
   */
  if (!vm_sdcp_verify_identify_mac (self->sdcp, self->identify_nonce,
                                    enrollment_id, mac))
    {
      fpi_ssm_mark_failed (self->task_ssm,
                           fpi_device_error_new_msg (FP_DEVICE_ERROR_PROTO,
                                                     "sensor returned a match with an "
                                                     "invalid authentication MAC"));
      return;
    }

  SHA256 (enrollment_id, SDCP_SECRET_LEN, id_hash);
  match = vm_print_new (self, subfactor, id_hash);

  if (fpi_device_get_current_action (dev) == FPI_DEVICE_ACTION_VERIFY)
    {
      FpPrint *template = NULL;

      fpi_device_get_verify_data (dev, &template);

      if (template && fp_print_equal (template, match))
        fpi_device_verify_report (dev, FPI_MATCH_SUCCESS, g_steal_pointer (&match), NULL);
      else
        fpi_device_verify_report (dev, FPI_MATCH_FAIL, NULL, NULL);
    }
  else
    {
      GPtrArray *templates = NULL;
      FpPrint *found = NULL;

      fpi_device_get_identify_data (dev, &templates);

      for (guint i = 0; templates && i < templates->len; i++)
        {
          FpPrint *candidate = g_ptr_array_index (templates, i);

          if (fp_print_equal (candidate, match))
            {
              found = candidate;
              break;
            }
        }

      fpi_device_identify_report (dev, found, g_steal_pointer (&match), NULL);
    }

  fpi_ssm_mark_completed (self->task_ssm);
}

static void
vm_verify_run_state (FpiSsm *ssm, FpDevice *dev)
{
  FpDeviceVerimark *self = FP_DEVICE_VERIMARK (dev);
  guint8 param[4] = { 0 };

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case VM_VERIFY_CAPTURE:
      vm_start_capture (self, VM_PURPOSE_IDENTIFY, vm_generic_cb);
      break;

    case VM_VERIFY_POLL:
      vm_poll_capture (self, VM_PURPOSE_IDENTIFY, vm_verify_poll_cb);
      break;

    case VM_VERIFY_ACCEPT:
      vm_accept_sample (self, VM_PURPOSE_IDENTIFY, vm_verify_accept_cb);
      break;

    case VM_VERIFY_NONCE:
      vm_sdcp_random (self->identify_nonce, sizeof (self->identify_nonce));
      vm_cmd (self, VM_IDENTIFY_NONCE, NULL, SDCP_RANDOM_LEN,
              self->identify_nonce, SDCP_RANDOM_LEN, FALSE, FALSE, vm_generic_cb);
      break;

    case VM_VERIFY_IDENTIFY_STATE:
      param[0] = 0x00;
      param[1] = 0x02;
      /* a no-match reply carries a non-zero status; that is not an error */
      vm_cmd (self, VM_IDENTIFY, param, VM_IDENTIFY_REPLY_LEN, NULL, 0,
              TRUE, FALSE, vm_identify_cb);
      break;

    default:
      g_assert_not_reached ();
    }
}

static void
vm_verify_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpDeviceVerimark *self = FP_DEVICE_VERIMARK (dev);

  self->task_ssm = NULL;

  if (fpi_device_get_current_action (dev) == FPI_DEVICE_ACTION_VERIFY)
    fpi_device_verify_complete (dev, error);
  else
    fpi_device_identify_complete (dev, error);
}

static void
vm_verify_identify (FpDevice *device)
{
  FpDeviceVerimark *self = FP_DEVICE_VERIMARK (device);

  self->purpose = VM_PURPOSE_IDENTIFY;
  self->task_ssm = fpi_ssm_new (device, vm_verify_run_state, VM_VERIFY_NUM_STATES);
  fpi_ssm_start (self->task_ssm, vm_verify_done);
}

/* ------------------------------------------------------------------------ */
/* list / delete                                                             */
/* ------------------------------------------------------------------------ */

static void
vm_list_cb (FpDeviceVerimark *self, guint8 *data, GError *error)
{
  FpDevice *dev = FP_DEVICE (self);
  g_autoptr(GPtrArray) prints = NULL;

  if (error)
    {
      fpi_device_list_complete (dev, NULL, error);
      return;
    }

  prints = g_ptr_array_new_with_free_func (g_object_unref);

  for (gint i = 0; i < self->slot_count; i++)
    {
      const guint8 *rec = data + (gsize) i * VM_TEMPLATE_STRIDE;

      if (rec[VM_REC_VALID_OFF] == 0)
        continue;

      g_ptr_array_add (prints,
                       g_object_ref_sink (vm_print_new (self,
                                                        rec[VM_REC_SUBFACTOR_OFF],
                                                        rec + VM_REC_ID_OFF)));
    }

  fp_dbg ("%u template(s) on device", prints->len);
  fpi_device_list_complete (dev, g_steal_pointer (&prints), NULL);
}

static void
vm_list (FpDevice *device)
{
  FpDeviceVerimark *self = FP_DEVICE_VERIMARK (device);

  vm_cmd (self, VM_GET_TEMPLATE, NULL,
          (guint16) (VM_TEMPLATE_STRIDE * self->slot_count),
          NULL, 0, FALSE, FALSE, vm_list_cb);
}

enum {
  VM_DELETE_FIND = 0,
  VM_DELETE_RECORD_STATE,
  VM_DELETE_NUM_STATES,
};

static void
vm_delete_find_cb (FpDeviceVerimark *self, guint8 *data, GError *error)
{
  FpPrint *print = NULL;
  guint8 wanted[VM_REC_ID_LEN];

  if (error)
    {
      fpi_ssm_mark_failed (self->task_ssm, error);
      return;
    }

  fpi_device_get_delete_data (FP_DEVICE (self), &print);

  if (!vm_print_get_id (print, wanted, NULL))
    {
      fpi_ssm_mark_failed (self->task_ssm,
                           fpi_device_error_new_msg (FP_DEVICE_ERROR_DATA_INVALID,
                                                     "print does not carry a usable "
                                                     "device identifier"));
      return;
    }

  self->delete_slot = -1;
  for (gint i = 0; i < self->slot_count; i++)
    {
      const guint8 *rec = data + (gsize) i * VM_TEMPLATE_STRIDE;

      if (rec[VM_REC_VALID_OFF] == 0)
        continue;

      if (memcmp (rec + VM_REC_ID_OFF, wanted, VM_REC_ID_LEN) == 0)
        {
          self->delete_slot = i;
          break;
        }
    }

  if (self->delete_slot < 0)
    {
      fpi_ssm_mark_failed (self->task_ssm,
                           fpi_device_error_new_msg (FP_DEVICE_ERROR_DATA_NOT_FOUND,
                                                     "no matching template on device"));
      return;
    }

  fpi_ssm_next_state (self->task_ssm);
}

static void
vm_delete_run_state (FpiSsm *ssm, FpDevice *dev)
{
  FpDeviceVerimark *self = FP_DEVICE_VERIMARK (dev);
  guint8 param[4] = { 0 };

  switch (fpi_ssm_get_cur_state (ssm))
    {
    case VM_DELETE_FIND:
      vm_cmd (self, VM_GET_TEMPLATE, NULL,
              (guint16) (VM_TEMPLATE_STRIDE * self->slot_count),
              NULL, 0, FALSE, FALSE, vm_delete_find_cb);
      break;

    case VM_DELETE_RECORD_STATE:
      /*
       * Guard hard: param 0xFF means "erase every template" on this firmware.
       * Only ever pass a slot index we actually located.
       */
      g_assert (self->delete_slot >= 0 && self->delete_slot < VM_MAX_SLOTS);
      param[0] = (guint8) self->delete_slot;
      vm_cmd (self, VM_DELETE_RECORD, param, 0, NULL, 0, FALSE, FALSE,
              vm_generic_cb);
      break;

    default:
      g_assert_not_reached ();
    }
}

static void
vm_delete_done (FpiSsm *ssm, FpDevice *dev, GError *error)
{
  FpDeviceVerimark *self = FP_DEVICE_VERIMARK (dev);

  self->task_ssm = NULL;
  fpi_device_delete_complete (dev, error);
}

static void
vm_delete (FpDevice *device)
{
  FpDeviceVerimark *self = FP_DEVICE_VERIMARK (device);

  self->delete_slot = -1;
  self->task_ssm = fpi_ssm_new (device, vm_delete_run_state, VM_DELETE_NUM_STATES);
  fpi_ssm_start (self->task_ssm, vm_delete_done);
}

/* ------------------------------------------------------------------------ */
/* cancel                                                                    */
/* ------------------------------------------------------------------------ */

static void
vm_cancel (FpDevice *device)
{
  FpDeviceVerimark *self = FP_DEVICE_VERIMARK (device);
  guint8 param[4] = { self->purpose, 0x00, 0x00, 0x00 };

  if (!self->purpose)
    return;

  vm_cmd (self, VM_CANCEL_CAPTURE, param, 0, NULL, 0, TRUE, FALSE, NULL);
}

/* ------------------------------------------------------------------------ */
/* boilerplate                                                               */
/* ------------------------------------------------------------------------ */

static void
fp_device_verimark_init (FpDeviceVerimark *self)
{
  self->slot_count = VM_MAX_SLOTS;
  self->delete_slot = -1;
}

static void
fp_device_verimark_finalize (GObject *object)
{
  FpDeviceVerimark *self = FP_DEVICE_VERIMARK (object);

  g_clear_pointer (&self->sdcp, vm_sdcp_free);
  g_clear_pointer (&self->read_data, g_free);
  g_clear_pointer (&self->cmd_transfer, fpi_usb_transfer_unref);
  g_clear_pointer (&self->data_transfer, fpi_usb_transfer_unref);

  G_OBJECT_CLASS (fp_device_verimark_parent_class)->finalize (object);
}

static void
fp_device_verimark_class_init (FpDeviceVerimarkClass *klass)
{
  GObjectClass *object_class = G_OBJECT_CLASS (klass);
  FpDeviceClass *dev_class = FP_DEVICE_CLASS (klass);

  object_class->finalize = fp_device_verimark_finalize;

  dev_class->id = "verimark";
  dev_class->full_name = "Kensington VeriMark Desktop 2.0";
  dev_class->type = FP_DEVICE_TYPE_USB;
  dev_class->id_table = id_table;
  dev_class->scan_type = FP_SCAN_TYPE_PRESS;
  dev_class->nr_enroll_stages = VM_ENROLL_STAGES;

  dev_class->open = vm_open;
  dev_class->close = vm_close;
  dev_class->enroll = vm_enroll;
  dev_class->verify = vm_verify_identify;
  dev_class->identify = vm_verify_identify;
  dev_class->list = vm_list;
  dev_class->delete = vm_delete;
  dev_class->cancel = vm_cancel;

  fpi_device_class_auto_initialize_features (dev_class);
}

/* ------------------------------------------------------------------------ */
/* TOD entry point                                                           */
/* ------------------------------------------------------------------------ */

/*
 * libfprint-tod dlsym()s this symbol out of the shared object and uses the
 * returned GType as the driver.
 */
G_MODULE_EXPORT GType fpi_tod_shared_driver_get_type (void);

G_MODULE_EXPORT GType
fpi_tod_shared_driver_get_type (void)
{
  return FP_TYPE_DEVICE_VERIMARK;
}

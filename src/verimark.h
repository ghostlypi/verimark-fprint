/*
 * Kensington VeriMark Desktop 2.0 fingerprint driver
 *
 * SPDX-License-Identifier: BSD-3-Clause
 * Copyright (c) 2026, Parth Iyer
 *
 * Protocol constants, reverse engineered from a USB capture of the Windows
 * driver and verified against the hardware. The transport is the Realtek
 * RTS5816-class bulk protocol; enrollment is gated behind Microsoft's Secure
 * Device Connection Protocol (SDCP).
 */

#pragma once

#include "drivers_api.h"

G_BEGIN_DECLS

#define FP_TYPE_DEVICE_VERIMARK (fp_device_verimark_get_type ())
G_DECLARE_FINAL_TYPE (FpDeviceVerimark, fp_device_verimark, FP, DEVICE_VERIMARK, FpDevice)

/* ---- USB ---------------------------------------------------------------- */
#define VERIMARK_VID 0x047d
#define VERIMARK_PID 0x8228

#define EP_OUT (1 | FPI_USB_ENDPOINT_OUT)      /* 0x01 */
#define EP_IN  (2 | FPI_USB_ENDPOINT_IN)       /* 0x82 */

#define EP_IN_MAX_BUF_SIZE 2048

#define CMD_TIMEOUT    1000
#define DATA_TIMEOUT   5000
#define STATUS_TIMEOUT 2000

/* ---- command framing ---------------------------------------------------- */
/*
 * Every command is a 12-byte packet on EP_OUT:
 *   [cmd0][cmd1][param 4][addr 4][data_len u16le]
 * The top two bits of cmd0 select the transfer shape.
 */
#define CMD_PKT_LEN 12

typedef enum {
  VM_CMD_NONE  = 0,   /* status only            */
  VM_CMD_READ  = 1,   /* device -> host payload */
  VM_CMD_WRITE = 2,   /* host -> device payload */
} VerimarkCmdType;

#define VM_CMD_TYPE(cmd0) (((cmd0) & 0xC0) >> 6)

/* status packet is 5 bytes: [status u8][err i32le] */
#define STATUS_LEN 5

/* ---- opcodes ------------------------------------------------------------ */
#define VM_GET_PROP        0x40, 0x06   /* read, index in param, 8 bytes    */
#define VM_SELECT_OS       0x05, 0x13   /* none, param[0] = os              */
#define VM_GET_ENROLL_NUM  0x45, 0x0D   /* read 2: [?][capacity]            */
#define VM_GET_TEMPLATE    0x45, 0x0E   /* read slots * VM_TEMPLATE_STRIDE  */
#define VM_START_CAPTURE   0x05, 0x05   /* none, param = [purpose, 0x02]    */
#define VM_POLL_CAPTURE    0x45, 0x06   /* read 5, param = [purpose, 0x02]  */
#define VM_ACCEPT_SAMPLE   0x45, 0x08   /* read 9, param = [purpose]        */
#define VM_CANCEL_CAPTURE  0x05, 0x07   /* none, param = [purpose]          */
#define VM_CHECK_DUPLICATE 0x45, 0x10   /* read 34, param = [1]             */
#define VM_DELETE_RECORD   0x05, 0x0F   /* none, param = [slot]             */

/* SDCP */
#define VM_SDCP_CONNECT        0x85, 0x01   /* write 101  */
#define VM_SDCP_CONNECT_RESP   0x45, 0x02   /* read 1206  */
#define VM_SDCP_RECONNECT      0x85, 0x03   /* write 34   */
#define VM_SDCP_RECONNECT_RESP 0x45, 0x04   /* read 34    */
#define VM_ENROLL_NONCE        0x45, 0x09   /* read 32, param = [purpose]   */
#define VM_ENROLL_COMMIT       0x85, 0x0A   /* write 49, param = [subfactor]*/
#define VM_IDENTIFY_NONCE      0x85, 0x0B   /* write 32                     */
#define VM_IDENTIFY            0x45, 0x0C   /* read 74, param = [0, 0x02]   */

/*
 * DANGER: 05 0F with param 0xFF is delete-everything. Only ever pass a real
 * slot index. Also note 85 21 (upstream libfprint's commit opcode) is NOT
 * implemented by this firmware and probing it wedges the chip until it is
 * physically unplugged.
 */
#define VM_DELETE_ALL_PARAM 0xFF

/* ---- storage layout ----------------------------------------------------- */
/*
 * The template table is slots * 52 bytes. Upstream libfprint's realtek driver
 * assumes 35, which misaligns every slot after the first on this firmware.
 *
 *   [0]     valid flag
 *   [1]     sub-template count
 *   [2]     subfactor (echoes the commit's param[0])
 *   [3..34] SHA-256 of the enrollment_id
 *   [35..41] 7 bytes of opaque host metadata, stored verbatim
 *   [42..51] padding
 */
#define VM_TEMPLATE_STRIDE   52
#define VM_MAX_SLOTS         10
#define VM_TEMPLATE_TABLE_LEN (VM_TEMPLATE_STRIDE * VM_MAX_SLOTS)

#define VM_REC_VALID_OFF     0
#define VM_REC_SUBFACTOR_OFF 2
#define VM_REC_ID_OFF        3
#define VM_REC_ID_LEN        32

#define VM_SUBFACTOR 0xF5

/* commit payload: enrollment_id || 17 bytes host metadata */
#define VM_COMMIT_PAYLOAD_LEN 49

/* identify reply: [status][subfactor][enrollment_id 32][mac 32][8] */
#define VM_IDENTIFY_REPLY_LEN 74
#define VM_IDENT_ID_OFF   2
#define VM_IDENT_MAC_OFF  34

/* ---- purposes and statuses ---------------------------------------------- */
typedef enum {
  VM_PURPOSE_VERIFY   = 0x01,
  VM_PURPOSE_IDENTIFY = 0x02,
  VM_PURPOSE_ENROLL   = 0x04,
} VerimarkPurpose;

/* first byte of a sample/identify reply */
typedef enum {
  VM_SUCCESS = 0x00,
  VM_TOO_HIGH,
  VM_TOO_LOW,
  VM_TOO_LEFT,
  VM_TOO_RIGHT,
  VM_TOO_FAST,
  VM_TOO_SLOW,
  VM_POOR_QUALITY,
  VM_TOO_SKEWED,
  VM_TOO_SHORT,
  VM_MERGE_FAILURE,
  VM_MATCH_FAIL,          /* 0x0b — "no match" / "no duplicate", not an error */
  VM_CMD_ERR,
} VerimarkInStatus;

/* poll reply byte 0 */
#define VM_CAPTURE_DONE      0x00
#define VM_CAPTURE_PRESENT   0x01
#define VM_CAPTURE_NO_FINGER 0x03

/*
 * Windows Hello takes 12 good samples. The firmware gives no "enrollment
 * complete" signal, so the host picks the count.
 */
#define VM_ENROLL_STAGES 12

G_END_DECLS

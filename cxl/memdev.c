// SPDX-License-Identifier: GPL-2.0
/* Copyright (C) 2020-2021 Intel Corporation. All rights reserved. */
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <util/log.h>
#include <util/filter.h>
#include <util/parse-options.h>
#include <ccan/list/list.h>
#include <ccan/minmax/minmax.h>
#include <ccan/array_size/array_size.h>
#include <ccan/endian/endian.h>
#include <ccan/short_types/short_types.h>
#include <cxl/libcxl.h>



struct action_context {
  FILE *f_out;
  FILE *f_in;
};

static struct parameters {
  const char *outfile;
  const char *infile;
  unsigned len;
  unsigned offset;
  bool verbose;
} param;

#define fail(fmt, ...) \
do { \
  fprintf(stderr, "cxl-%s:%s:%d: " fmt, \
      VERSION, __func__, __LINE__, ##__VA_ARGS__); \
} while (0)

#define BASE_OPTIONS() \
OPT_BOOLEAN('v',"verbose", &param.verbose, "turn on debug")

#define READ_OPTIONS() \
OPT_STRING('o', "output", &param.outfile, "output-file", \
  "filename to write label area contents")

#define WRITE_OPTIONS() \
OPT_STRING('i', "input", &param.infile, "input-file", \
  "filename to read label area data")

#define LABEL_OPTIONS() \
OPT_UINTEGER('s', "size", &param.len, "number of label bytes to operate"), \
OPT_UINTEGER('O', "offset", &param.offset, \
  "offset into the label area to start operation")

static const struct option read_options[] = {
  BASE_OPTIONS(),
  LABEL_OPTIONS(),
  READ_OPTIONS(),
  OPT_END(),
};

static const struct option write_options[] = {
  BASE_OPTIONS(),
  LABEL_OPTIONS(),
  WRITE_OPTIONS(),
  OPT_END(),
};

static const struct option zero_options[] = {
  BASE_OPTIONS(),
  LABEL_OPTIONS(),
  OPT_END(),
};

static const struct option cmd_identify_options[] = {
  BASE_OPTIONS(),
  OPT_END(),
};

static const struct option cmd_get_supported_logs_options[] = {
  BASE_OPTIONS(),
  OPT_END(),
};

static const struct option cmd_get_cel_log_options[] = {
  BASE_OPTIONS(),
  OPT_END(),
};

static const struct option cmd_get_event_interrupt_policy_options[] = {
  BASE_OPTIONS(),
  OPT_END(),
};

static struct _interrupt_policy_params {
  u32 policy;
  bool verbose;
} interrupt_policy_params;


#define SET_INTERRUPT_POLICY_OPTIONS() \
OPT_UINTEGER('i', "int_policy", &interrupt_policy_params.policy, "Set event interrupt policy. Fields: Informational Event Log Interrupt Settings (1B), Warning Event Log Interrupt Settings (1B), Failure Event Log Interrupt Settings (1B), Fatal Event Log Interrupt Settings (1B)")

static const struct option cmd_set_event_interrupt_policy_options[] = {
  BASE_OPTIONS(),
  SET_INTERRUPT_POLICY_OPTIONS(),
  OPT_END(),
};

static const struct option cmd_get_timestamp_options[] = {
  BASE_OPTIONS(),
  OPT_END(),
};

static struct _ts_params {
  u64 timestamp;
  bool verbose;
} ts_params;


#define SET_TIMESTAMP_OPTIONS() \
OPT_U64('t', "timestamp", &ts_params.timestamp, "Set the timestamp on the device")

static const struct option cmd_set_timestamp_options[] = {
  BASE_OPTIONS(),
  SET_TIMESTAMP_OPTIONS(),
  OPT_END(),
};

static struct _update_fw_params {
  const char *filepath;
  u32 slot;
  bool hbo;
  bool mock;
  bool verbose;
} update_fw_params;

#define UPDATE_FW_OPTIONS() \
OPT_FILENAME('f', "file", &update_fw_params.filepath, "rom-file", \
  "filepath to read ROM for firmware update"), \
OPT_UINTEGER('s', "slot", &update_fw_params.slot, "slot to use for firmware loading"), \
OPT_BOOLEAN('b', "background", &update_fw_params.hbo, "runs as hidden background option"), \
OPT_BOOLEAN('m', "mock", &update_fw_params.mock, "For testing purposes. Mock transfer with only 1 continue then abort")

static const struct option cmd_update_fw_options[] = {
  BASE_OPTIONS(),
  UPDATE_FW_OPTIONS(),
  OPT_END(),
};




static const struct option cmd_device_info_get_options[] = {
  BASE_OPTIONS(),
  OPT_END(),
};




static const struct option cmd_get_fw_info_options[] = {
  BASE_OPTIONS(),
  OPT_END(),
};

static struct _activate_fw_params {
  u32 action;
  u32 slot;
  bool verbose;
} activate_fw_params;


#define ACTIVATE_FW_OPTIONS() \
OPT_UINTEGER('a', "action", &activate_fw_params.action, "Action"), \
OPT_UINTEGER('s', "slot", &activate_fw_params.slot, "Slot")

static const struct option cmd_activate_fw_options[] = {
  BASE_OPTIONS(),
  ACTIVATE_FW_OPTIONS(),
  OPT_END(),
};

static const struct option cmd_get_alert_config_options[] = {
  BASE_OPTIONS(),
  OPT_END(),
};

static struct _alert_config_params {
  u32 alert_prog_threshold;
  u32 device_temp_threshold;
  u32 mem_error_threshold;
  bool verbose;
} alert_config_params;


#define SET_ALERT_CONFIG_OPTIONS() \
OPT_UINTEGER('a', "alert_prog_threshold", &alert_config_params.alert_prog_threshold, "Set valid, enable alert actions and life used programmable threshold. Fields: Valid Alert Actions (1B), Enable Alert Actions (1B), Life Used Programmable Warning Threshold (1B)"), \
OPT_UINTEGER('d', "device_temp_threshold", &alert_config_params.device_temp_threshold, "Set device over/under temp thresholds. Fields: Device Over-Temperature Programmable Warning Threshold (2B), Device Under-Temperature Programmable Warning Threshold (2B)"), \
OPT_UINTEGER('m', "mem_error_threshold", &alert_config_params.mem_error_threshold, "Set memory corrected thresholds. Fields: Corrected Volatile Memory Error Programmable Warning Threshold (2B), Corrected Persistent Memory Error Programmable Warning Threshold (2B)")

static const struct option cmd_set_alert_config_options[] = {
  BASE_OPTIONS(),
  SET_ALERT_CONFIG_OPTIONS(),
  OPT_END(),
};

static const struct option cmd_get_health_info_options[] = {
  BASE_OPTIONS(),
  OPT_END(),
};



static const struct option cmd_get_ld_info_options[] = {
  BASE_OPTIONS(),
  OPT_END(),
};

static struct _ddr_info_params {
  bool verbose;
  int ddr_id;
} ddr_info_params;


#define DDR_INFO_OPTIONS() \
OPT_INTEGER('i', "ddr_id", &ddr_info_params.ddr_id, "DDR instance id")


static const struct option cmd_ddr_info_options[] = {
  BASE_OPTIONS(),
  DDR_INFO_OPTIONS(),
  OPT_END(),
};

static struct _get_event_records_params {
  int event_log_type; /* 00 - information, 01 - warning, 02 - failure, 03 - fatal */
  bool verbose;
} get_event_records_params;


#define GET_EVENT_RECORDS_OPTIONS() \
OPT_INTEGER('t', "log_type", &get_event_records_params.event_log_type, "Event log type (00 - information (default), 01 - warning, 02 - failure, 03 - fatal)")

static const struct option cmd_get_event_records_options[] = {
  BASE_OPTIONS(),
  GET_EVENT_RECORDS_OPTIONS(),
  OPT_END(),
};

static struct _clear_event_records_params {
  int event_log_type; /* 00 - information, 01 - warning, 02 - failure, 03 - fatal */
  int clear_event_flags; /* bit 0 - when set, clears all events */
  unsigned event_record_handle; /* only one is supported */
  bool verbose;
} clear_event_records_params;


#define CLEAR_EVENT_RECORDS_OPTIONS() \
OPT_INTEGER('t', "log_type", &clear_event_records_params.event_log_type, "Event log type (00 - information (default), 01 - warning, 02 - failure, 03 - fatal)"), \
OPT_INTEGER('f', "event_flag", &clear_event_records_params.clear_event_flags, "Clear Event Flags: 1 - clear all events, 0 (default) - clear specific event record"), \
OPT_UINTEGER('i', "event_record_handle", &clear_event_records_params.event_record_handle, "Clear Specific Event specific by Event Record Handle")

static const struct option cmd_clear_event_records_options[] = {
  BASE_OPTIONS(),
  CLEAR_EVENT_RECORDS_OPTIONS(),
  OPT_END(),
};

static struct _hct_start_stop_trigger_params {
  u32 hct_inst;
  u32 buf_control;
  bool verbose;
} hct_start_stop_trigger_params;


#define HCT_START_STOP_TRIGGER_OPTIONS() \
OPT_UINTEGER('i', "hct_inst", &hct_start_stop_trigger_params.hct_inst, "HCT Instance"), \
OPT_UINTEGER('b', "buf_control", &hct_start_stop_trigger_params.buf_control, "Buffer Control")

static const struct option cmd_hct_start_stop_trigger_options[] = {
  BASE_OPTIONS(),
  HCT_START_STOP_TRIGGER_OPTIONS(),
  OPT_END(),
};

static struct _hct_get_buffer_status_params {
  u32 hct_inst;
  bool verbose;
} hct_get_buffer_status_params;


#define HCT_GET_BUFFER_STATUS_OPTIONS() \
OPT_UINTEGER('i', "hct_inst", &hct_get_buffer_status_params.hct_inst, "HCT Instance")

static const struct option cmd_hct_get_buffer_status_options[] = {
  BASE_OPTIONS(),
  HCT_GET_BUFFER_STATUS_OPTIONS(),
  OPT_END(),
};

static struct _hct_enable_params {
  u32 hct_inst;
  bool verbose;
} hct_enable_params;


#define HCT_ENABLE_OPTIONS() \
OPT_UINTEGER('i', "hct_inst", &hct_enable_params.hct_inst, "HCT Instance")

static const struct option cmd_hct_enable_options[] = {
  BASE_OPTIONS(),
  HCT_ENABLE_OPTIONS(),
  OPT_END(),
};

static struct _ltmon_capture_clear_params {
  u32 cxl_mem_id;
  bool verbose;
} ltmon_capture_clear_params;


#define LTMON_CAPTURE_CLEAR_OPTIONS() \
OPT_UINTEGER('c', "cxl_mem_id", &ltmon_capture_clear_params.cxl_mem_id, "CXL.MEM ID")

static const struct option cmd_ltmon_capture_clear_options[] = {
  BASE_OPTIONS(),
  LTMON_CAPTURE_CLEAR_OPTIONS(),
  OPT_END(),
};

static struct _ltmon_capture_params {
  u32 cxl_mem_id;
  u32 capt_mode;
  u32 ignore_sub_chg;
  u32 ignore_rxl0_chg;
  u32 trig_src_sel;
  bool verbose;
} ltmon_capture_params;


#define LTMON_CAPTURE_OPTIONS() \
OPT_UINTEGER('c', "cxl_mem_id", &ltmon_capture_params.cxl_mem_id, "CXL.MEM ID"), \
OPT_UINTEGER('d', "capt_mode", &ltmon_capture_params.capt_mode, "Capture Mode"), \
OPT_UINTEGER('i', "ignore_sub_chg", &ltmon_capture_params.ignore_sub_chg, "Ignore Sub Change"), \
OPT_UINTEGER('j', "ignore_rxl0_chg", &ltmon_capture_params.ignore_rxl0_chg, "Ignore Receiver L0 Change"), \
OPT_UINTEGER('t', "trig_src_sel", &ltmon_capture_params.trig_src_sel, "Trigger Source Selection")

static const struct option cmd_ltmon_capture_options[] = {
  BASE_OPTIONS(),
  LTMON_CAPTURE_OPTIONS(),
  OPT_END(),
};

static struct _ltmon_capture_freeze_and_restore_params {
  u32 cxl_mem_id;
  u32 freeze_restore;
  bool verbose;
} ltmon_capture_freeze_and_restore_params;


#define LTMON_CAPTURE_FREEZE_AND_RESTORE_OPTIONS() \
OPT_UINTEGER('c', "cxl_mem_id", &ltmon_capture_freeze_and_restore_params.cxl_mem_id, "CXL.MEM ID"), \
OPT_UINTEGER('f', "freeze_restore", &ltmon_capture_freeze_and_restore_params.freeze_restore, "Freeze Restore")

static const struct option cmd_ltmon_capture_freeze_and_restore_options[] = {
  BASE_OPTIONS(),
  LTMON_CAPTURE_FREEZE_AND_RESTORE_OPTIONS(),
  OPT_END(),
};

static struct _ltmon_l2r_count_dump_params {
  u32 cxl_mem_id;
  bool verbose;
} ltmon_l2r_count_dump_params;


#define LTMON_L2R_COUNT_DUMP_OPTIONS() \
OPT_UINTEGER('c', "cxl_mem_id", &ltmon_l2r_count_dump_params.cxl_mem_id, "CXL.MEM ID")

static const struct option cmd_ltmon_l2r_count_dump_options[] = {
  BASE_OPTIONS(),
  LTMON_L2R_COUNT_DUMP_OPTIONS(),
  OPT_END(),
};

static struct _ltmon_l2r_count_clear_params {
  u32 cxl_mem_id;
  bool verbose;
} ltmon_l2r_count_clear_params;


#define LTMON_L2R_COUNT_CLEAR_OPTIONS() \
OPT_UINTEGER('c', "cxl_mem_id", &ltmon_l2r_count_clear_params.cxl_mem_id, "CXL.MEM ID")

static const struct option cmd_ltmon_l2r_count_clear_options[] = {
  BASE_OPTIONS(),
  LTMON_L2R_COUNT_CLEAR_OPTIONS(),
  OPT_END(),
};

static struct _ltmon_basic_cfg_params {
  u32 cxl_mem_id;
  u32 tick_cnt;
  u32 global_ts;
  bool verbose;
} ltmon_basic_cfg_params;


#define LTMON_BASIC_CFG_OPTIONS() \
OPT_UINTEGER('c', "cxl_mem_id", &ltmon_basic_cfg_params.cxl_mem_id, "CXL.MEM ID"), \
OPT_UINTEGER('t', "tick_cnt", &ltmon_basic_cfg_params.tick_cnt, "Tick Count"), \
OPT_UINTEGER('g', "global_ts", &ltmon_basic_cfg_params.global_ts, "Global Time Stamp")

static const struct option cmd_ltmon_basic_cfg_options[] = {
  BASE_OPTIONS(),
  LTMON_BASIC_CFG_OPTIONS(),
  OPT_END(),
};

static struct _ltmon_watch_params {
  u32 cxl_mem_id;
  u32 watch_id;
  u32 watch_mode;
  u32 src_maj_st;
  u32 src_min_st;
  u32 src_l0_st;
  u32 dst_maj_st;
  u32 dst_min_st;
  u32 dst_l0_st;
  bool verbose;
} ltmon_watch_params;


#define LTMON_WATCH_OPTIONS() \
OPT_UINTEGER('c', "cxl_mem_id", &ltmon_watch_params.cxl_mem_id, "CXL.MEM ID"), \
OPT_UINTEGER('w', "watch_id", &ltmon_watch_params.watch_id, "Watch ID"), \
OPT_UINTEGER('x', "watch_mode", &ltmon_watch_params.watch_mode, "Watch Mode"), \
OPT_UINTEGER('s', "src_maj_st", &ltmon_watch_params.src_maj_st, "Source Maj State"), \
OPT_UINTEGER('t', "src_min_st", &ltmon_watch_params.src_min_st, "Source Min State"), \
OPT_UINTEGER('u', "src_l0_st", &ltmon_watch_params.src_l0_st, "Source L0 State"), \
OPT_UINTEGER('d', "dst_maj_st", &ltmon_watch_params.dst_maj_st, "Destination Maj State"), \
OPT_UINTEGER('e', "dst_min_st", &ltmon_watch_params.dst_min_st, "Destination Min State"), \
OPT_UINTEGER('f', "dst_l0_st", &ltmon_watch_params.dst_l0_st, "Destination L0 State")

static const struct option cmd_ltmon_watch_options[] = {
  BASE_OPTIONS(),
  LTMON_WATCH_OPTIONS(),
  OPT_END(),
};

static struct _ltmon_capture_stat_params {
  u32 cxl_mem_id;
  bool verbose;
} ltmon_capture_stat_params;


#define LTMON_CAPTURE_STAT_OPTIONS() \
OPT_UINTEGER('c', "cxl_mem_id", &ltmon_capture_stat_params.cxl_mem_id, "CXL.MEM ID")

static const struct option cmd_ltmon_capture_stat_options[] = {
  BASE_OPTIONS(),
  LTMON_CAPTURE_STAT_OPTIONS(),
  OPT_END(),
};

static struct _ltmon_capture_log_dmp_params {
  u32 cxl_mem_id;
  u32 dump_idx;
  u32 dump_cnt;
  bool verbose;
} ltmon_capture_log_dmp_params;


#define LTMON_CAPTURE_LOG_DMP_OPTIONS() \
OPT_UINTEGER('c', "cxl_mem_id", &ltmon_capture_log_dmp_params.cxl_mem_id, "CXL.MEM ID"), \
OPT_UINTEGER('d', "dump_idx", &ltmon_capture_log_dmp_params.dump_idx, "Dump Index"), \
OPT_UINTEGER('e', "dump_cnt", &ltmon_capture_log_dmp_params.dump_cnt, "Dump Count")

static const struct option cmd_ltmon_capture_log_dmp_options[] = {
  BASE_OPTIONS(),
  LTMON_CAPTURE_LOG_DMP_OPTIONS(),
  OPT_END(),
};

static struct _ltmon_capture_trigger_params {
  u32 cxl_mem_id;
  u32 trig_src;
  bool verbose;
} ltmon_capture_trigger_params;


#define LTMON_CAPTURE_TRIGGER_OPTIONS() \
OPT_UINTEGER('c', "cxl_mem_id", &ltmon_capture_trigger_params.cxl_mem_id, "CXL.MEM ID"), \
OPT_UINTEGER('t', "trig_src", &ltmon_capture_trigger_params.trig_src, "Trigger Source")

static const struct option cmd_ltmon_capture_trigger_options[] = {
  BASE_OPTIONS(),
  LTMON_CAPTURE_TRIGGER_OPTIONS(),
  OPT_END(),
};

static struct _ltmon_enable_params {
  u32 cxl_mem_id;
  u32 enable;
  bool verbose;
} ltmon_enable_params;


#define LTMON_ENABLE_OPTIONS() \
OPT_UINTEGER('c', "cxl_mem_id", &ltmon_enable_params.cxl_mem_id, "CXL.MEM ID"), \
OPT_UINTEGER('e', "enable", &ltmon_enable_params.enable, "Enable")

static const struct option cmd_ltmon_enable_options[] = {
  BASE_OPTIONS(),
  LTMON_ENABLE_OPTIONS(),
  OPT_END(),
};

static struct _osa_os_type_trig_cfg_params {
  u32 cxl_mem_id;
  u32 lane_mask;
  u32 lane_dir_mask;
  u32 rate_mask;
  u32 os_type_mask;
  bool verbose;
} osa_os_type_trig_cfg_params;


#define OSA_OS_TYPE_TRIG_CFG_OPTIONS() \
OPT_UINTEGER('c', "cxl_mem_id", &osa_os_type_trig_cfg_params.cxl_mem_id, "CXL.MEM ID"), \
OPT_UINTEGER('l', "lane_mask", &osa_os_type_trig_cfg_params.lane_mask, "Lane Mask"), \
OPT_UINTEGER('m', "lane_dir_mask", &osa_os_type_trig_cfg_params.lane_dir_mask, "Lane Direction Mask (see OSA_LANE_DIR_BITMSK_*)"), \
OPT_UINTEGER('r', "rate_mask", &osa_os_type_trig_cfg_params.rate_mask, "Link Rate mask (see OSA_LINK_RATE_BITMSK_*)"), \
OPT_UINTEGER('o', "os_type_mask", &osa_os_type_trig_cfg_params.os_type_mask, "OS Type mask (see OSA_OS_TYPE_TRIG_BITMSK_*)")

static const struct option cmd_osa_os_type_trig_cfg_options[] = {
  BASE_OPTIONS(),
  OSA_OS_TYPE_TRIG_CFG_OPTIONS(),
  OPT_END(),
};

static struct _osa_cap_ctrl_params {
  u32 cxl_mem_id;
  u32 lane_mask;
  u32 lane_dir_mask;
  u32 drop_single_os;
  u32 stop_mode;
  u32 snapshot_mode;
  u32 post_trig_num;
  u32 os_type_mask;
  bool verbose;
} osa_cap_ctrl_params;


#define OSA_CAP_CTRL_OPTIONS() \
OPT_UINTEGER('c', "cxl_mem_id", &osa_cap_ctrl_params.cxl_mem_id, "CXL.MEM ID"), \
OPT_UINTEGER('l', "lane_mask", &osa_cap_ctrl_params.lane_mask, "Lane Mask"), \
OPT_UINTEGER('m', "lane_dir_mask", &osa_cap_ctrl_params.lane_dir_mask, "Lane Direction Mask (see OSA_LANE_DIR_BITMSK_*)"), \
OPT_UINTEGER('d', "drop_single_os", &osa_cap_ctrl_params.drop_single_os, "Drop Single OS's (TS1/TS2/FTS/CTL_SKP)"), \
OPT_UINTEGER('s', "stop_mode", &osa_cap_ctrl_params.stop_mode, "Capture Stop Mode (see osa_cap_stop_mode_enum)"), \
OPT_UINTEGER('t', "snapshot_mode", &osa_cap_ctrl_params.snapshot_mode, "Snapshot Mode Enable"), \
OPT_UINTEGER('p', "post_trig_num", &osa_cap_ctrl_params.post_trig_num, "Number of post-trigger entries"), \
OPT_UINTEGER('o', "os_type_mask", &osa_cap_ctrl_params.os_type_mask, "OS Type mask (see OSA_OS_TYPE_CAP_BITMSK_*)")

static const struct option cmd_osa_cap_ctrl_options[] = {
  BASE_OPTIONS(),
  OSA_CAP_CTRL_OPTIONS(),
  OPT_END(),
};

static struct _osa_cfg_dump_params {
  u32 cxl_mem_id;
  bool verbose;
} osa_cfg_dump_params;


#define OSA_CFG_DUMP_OPTIONS() \
OPT_UINTEGER('c', "cxl_mem_id", &osa_cfg_dump_params.cxl_mem_id, "CXL.MEM ID")

static const struct option cmd_osa_cfg_dump_options[] = {
  BASE_OPTIONS(),
  OSA_CFG_DUMP_OPTIONS(),
  OPT_END(),
};

static struct _osa_ana_op_params {
  u32 cxl_mem_id;
  u32 op;
  bool verbose;
} osa_ana_op_params;


#define OSA_ANA_OP_OPTIONS() \
OPT_UINTEGER('c', "cxl_mem_id", &osa_ana_op_params.cxl_mem_id, "CXL.MEM ID"), \
OPT_UINTEGER('o', "op", &osa_ana_op_params.op, "Operation (see osa_op_enum)")

static const struct option cmd_osa_ana_op_options[] = {
  BASE_OPTIONS(),
  OSA_ANA_OP_OPTIONS(),
  OPT_END(),
};

static struct _osa_status_query_params {
  u32 cxl_mem_id;
  bool verbose;
} osa_status_query_params;


#define OSA_STATUS_QUERY_OPTIONS() \
OPT_UINTEGER('c', "cxl_mem_id", &osa_status_query_params.cxl_mem_id, "CXL.MEM ID")

static const struct option cmd_osa_status_query_options[] = {
  BASE_OPTIONS(),
  OSA_STATUS_QUERY_OPTIONS(),
  OPT_END(),
};

static struct _osa_access_rel_params {
  u32 cxl_mem_id;
  bool verbose;
} osa_access_rel_params;


#define OSA_ACCESS_REL_OPTIONS() \
OPT_UINTEGER('c', "cxl_mem_id", &osa_access_rel_params.cxl_mem_id, "CXL.MEM ID")

static const struct option cmd_osa_access_rel_options[] = {
  BASE_OPTIONS(),
  OSA_ACCESS_REL_OPTIONS(),
  OPT_END(),
};

static struct _perfcnt_mta_ltif_set_params {
  u32 counter;
  u32 match_value;
  u32 opcode;
  u32 meta_field;
  u32 meta_value;
  bool verbose;
} perfcnt_mta_ltif_set_params;


#define PERFCNT_MTA_LTIF_SET_OPTIONS() \
OPT_UINTEGER('c', "counter", &perfcnt_mta_ltif_set_params.counter, "Counter"), \
OPT_UINTEGER('m', "match_value", &perfcnt_mta_ltif_set_params.match_value, "Match Value"), \
OPT_UINTEGER('o', "opcode", &perfcnt_mta_ltif_set_params.opcode, "Opcode"), \
OPT_UINTEGER('n', "meta_field", &perfcnt_mta_ltif_set_params.meta_field, "Meta Field"), \
OPT_UINTEGER('p', "meta_value", &perfcnt_mta_ltif_set_params.meta_value, "Meta Value")

static const struct option cmd_perfcnt_mta_ltif_set_options[] = {
  BASE_OPTIONS(),
  PERFCNT_MTA_LTIF_SET_OPTIONS(),
  OPT_END(),
};

static struct _perfcnt_mta_get_params {
  u32 type;
  u32 counter;
  bool verbose;
} perfcnt_mta_get_params;


#define PERFCNT_MTA_GET_OPTIONS() \
OPT_UINTEGER('t', "type", &perfcnt_mta_get_params.type, "Type"), \
OPT_UINTEGER('c', "counter", &perfcnt_mta_get_params.counter, "Counter")

static const struct option cmd_perfcnt_mta_get_options[] = {
  BASE_OPTIONS(),
  PERFCNT_MTA_GET_OPTIONS(),
  OPT_END(),
};

static struct _perfcnt_mta_latch_val_get_params {
  u32 type;
  u32 counter;
  bool verbose;
} perfcnt_mta_latch_val_get_params;


#define PERFCNT_MTA_LATCH_VAL_GET_OPTIONS() \
OPT_UINTEGER('t', "type", &perfcnt_mta_latch_val_get_params.type, "Type"), \
OPT_UINTEGER('c', "counter", &perfcnt_mta_latch_val_get_params.counter, "Counter")

static const struct option cmd_perfcnt_mta_latch_val_get_options[] = {
  BASE_OPTIONS(),
  PERFCNT_MTA_LATCH_VAL_GET_OPTIONS(),
  OPT_END(),
};

static struct _perfcnt_mta_counter_clear_params {
  u32 type;
  u32 counter;
  bool verbose;
} perfcnt_mta_counter_clear_params;


#define PERFCNT_MTA_COUNTER_CLEAR_OPTIONS() \
OPT_UINTEGER('t', "type", &perfcnt_mta_counter_clear_params.type, "Type"), \
OPT_UINTEGER('c', "counter", &perfcnt_mta_counter_clear_params.counter, "Counter")

static const struct option cmd_perfcnt_mta_counter_clear_options[] = {
  BASE_OPTIONS(),
  PERFCNT_MTA_COUNTER_CLEAR_OPTIONS(),
  OPT_END(),
};

static struct _perfcnt_mta_cnt_val_latch_params {
  u32 type;
  u32 counter;
  bool verbose;
} perfcnt_mta_cnt_val_latch_params;


#define PERFCNT_MTA_CNT_VAL_LATCH_OPTIONS() \
OPT_UINTEGER('t', "type", &perfcnt_mta_cnt_val_latch_params.type, "Type"), \
OPT_UINTEGER('c', "counter", &perfcnt_mta_cnt_val_latch_params.counter, "Counter")

static const struct option cmd_perfcnt_mta_cnt_val_latch_options[] = {
  BASE_OPTIONS(),
  PERFCNT_MTA_CNT_VAL_LATCH_OPTIONS(),
  OPT_END(),
};

static struct _perfcnt_mta_hif_set_params {
  u32 counter;
  u32 match_value;
  u32 addr;
  u32 req_ty;
  u32 sc_ty;
  bool verbose;
} perfcnt_mta_hif_set_params;


#define PERFCNT_MTA_HIF_SET_OPTIONS() \
OPT_UINTEGER('c', "counter", &perfcnt_mta_hif_set_params.counter, "Counter"), \
OPT_UINTEGER('m', "match_value", &perfcnt_mta_hif_set_params.match_value, "Match Value"), \
OPT_UINTEGER('a', "addr", &perfcnt_mta_hif_set_params.addr, "Address"), \
OPT_UINTEGER('r', "req_ty", &perfcnt_mta_hif_set_params.req_ty, "Req Type"), \
OPT_UINTEGER('s', "sc_ty", &perfcnt_mta_hif_set_params.sc_ty, "Scrub Req")

static const struct option cmd_perfcnt_mta_hif_set_options[] = {
  BASE_OPTIONS(),
  PERFCNT_MTA_HIF_SET_OPTIONS(),
  OPT_END(),
};

static struct _perfcnt_mta_hif_cfg_get_params {
  u32 counter;
  bool verbose;
} perfcnt_mta_hif_cfg_get_params;


#define PERFCNT_MTA_HIF_CFG_GET_OPTIONS() \
OPT_UINTEGER('c', "counter", &perfcnt_mta_hif_cfg_get_params.counter, "Counter")

static const struct option cmd_perfcnt_mta_hif_cfg_get_options[] = {
  BASE_OPTIONS(),
  PERFCNT_MTA_HIF_CFG_GET_OPTIONS(),
  OPT_END(),
};

static struct _perfcnt_mta_hif_latch_val_get_params {
  u32 counter;
  bool verbose;
} perfcnt_mta_hif_latch_val_get_params;


#define PERFCNT_MTA_HIF_LATCH_VAL_GET_OPTIONS() \
OPT_UINTEGER('c', "counter", &perfcnt_mta_hif_latch_val_get_params.counter, "Counter")

static const struct option cmd_perfcnt_mta_hif_latch_val_get_options[] = {
  BASE_OPTIONS(),
  PERFCNT_MTA_HIF_LATCH_VAL_GET_OPTIONS(),
  OPT_END(),
};

static struct _perfcnt_mta_hif_counter_clear_params {
  u32 counter;
  bool verbose;
} perfcnt_mta_hif_counter_clear_params;


#define PERFCNT_MTA_HIF_COUNTER_CLEAR_OPTIONS() \
OPT_UINTEGER('c', "counter", &perfcnt_mta_hif_counter_clear_params.counter, "Counter")

static const struct option cmd_perfcnt_mta_hif_counter_clear_options[] = {
  BASE_OPTIONS(),
  PERFCNT_MTA_HIF_COUNTER_CLEAR_OPTIONS(),
  OPT_END(),
};

static struct _perfcnt_mta_hif_cnt_val_latch_params {
  u32 counter;
  bool verbose;
} perfcnt_mta_hif_cnt_val_latch_params;


#define PERFCNT_MTA_HIF_CNT_VAL_LATCH_OPTIONS() \
OPT_UINTEGER('c', "counter", &perfcnt_mta_hif_cnt_val_latch_params.counter, "Counter")

static const struct option cmd_perfcnt_mta_hif_cnt_val_latch_options[] = {
  BASE_OPTIONS(),
  PERFCNT_MTA_HIF_CNT_VAL_LATCH_OPTIONS(),
  OPT_END(),
};

static struct _perfcnt_ddr_generic_select_params {
  u32 ddr_id;
  u32 cid;
  u32 rank;
  u32 bank;
  u32 bankgroup;
  u64 event;
  bool verbose;
} perfcnt_ddr_generic_select_params;


#define PERFCNT_DDR_GENERIC_SELECT_OPTIONS() \
OPT_UINTEGER('d', "ddr_id", &perfcnt_ddr_generic_select_params.ddr_id, "DDR instance"), \
OPT_UINTEGER('c', "cid", &perfcnt_ddr_generic_select_params.cid, "CID selection"), \
OPT_UINTEGER('r', "rank", &perfcnt_ddr_generic_select_params.rank, "Rank selection"), \
OPT_UINTEGER('b', "bank", &perfcnt_ddr_generic_select_params.bank, "Bank selection"), \
OPT_UINTEGER('e', "bankgroup", &perfcnt_ddr_generic_select_params.bankgroup, "Bank Group selection"), \
OPT_U64('f', "event", &perfcnt_ddr_generic_select_params.event, "Events selection")

static const struct option cmd_perfcnt_ddr_generic_select_options[] = {
  BASE_OPTIONS(),
  PERFCNT_DDR_GENERIC_SELECT_OPTIONS(),
  OPT_END(),
};

static struct _perfcnt_ddr_generic_capture_params {
	u32 ddr_id;
	u32 poll_period_ms;
	bool verbose;
} perfcnt_ddr_generic_capture_params;

#define PERFCNT_DDR_GENERIC_CAPTURE_BASE_OPTIONS() \
OPT_BOOLEAN('v',"verbose", &perfcnt_ddr_generic_capture_params.verbose, "turn on debug")

#define PERFCNT_DDR_GENERIC_CAPTURE_OPTIONS() \
OPT_UINTEGER('d', "ddr_id", &perfcnt_ddr_generic_capture_params.ddr_id, "DDR instance"), \
OPT_UINTEGER('c', "poll_period_ms", &perfcnt_ddr_generic_capture_params.poll_period_ms, "Capture-time in ms")

static const struct option cmd_perfcnt_ddr_generic_capture_options[] = {
	PERFCNT_DDR_GENERIC_CAPTURE_BASE_OPTIONS(),
	PERFCNT_DDR_GENERIC_CAPTURE_OPTIONS(),
	OPT_END(),
};

static struct _perfcnt_ddr_dfi_capture_params {
	u32 ddr_id;
	u32 poll_period_ms;
	bool verbose;
} perfcnt_ddr_dfi_capture_params;

#define PERFCNT_DDR_DFI_CAPTURE_BASE_OPTIONS() \
OPT_BOOLEAN('v',"verbose", &perfcnt_ddr_dfi_capture_params.verbose, "turn on debug")

#define PERFCNT_DDR_DFI_CAPTURE_OPTIONS() \
OPT_UINTEGER('d', "ddr_id", &perfcnt_ddr_dfi_capture_params.ddr_id, "DDR instance"), \
OPT_UINTEGER('c', "poll_period_ms", &perfcnt_ddr_dfi_capture_params.poll_period_ms, "Capture-time in ms")

static const struct option cmd_perfcnt_ddr_dfi_capture_options[] = {
	PERFCNT_DDR_DFI_CAPTURE_BASE_OPTIONS(),
	PERFCNT_DDR_DFI_CAPTURE_OPTIONS(),
	OPT_END(),
};


static struct _err_inj_drs_poison_params {
  u32 ch_id;
  u32 duration;
  u32 inj_mode;
  u32 tag;
  bool verbose;
} err_inj_drs_poison_params;


#define ERR_INJ_DRS_POISON_OPTIONS() \
OPT_UINTEGER('c', "ch_id", &err_inj_drs_poison_params.ch_id, "DRS channel"), \
OPT_UINTEGER('d', "duration", &err_inj_drs_poison_params.duration, "Duration"), \
OPT_UINTEGER('i', "inj_mode", &err_inj_drs_poison_params.inj_mode, "Injection mode"), \
OPT_UINTEGER('t', "tag", &err_inj_drs_poison_params.tag, "Tag")

static const struct option cmd_err_inj_drs_poison_options[] = {
  BASE_OPTIONS(),
  ERR_INJ_DRS_POISON_OPTIONS(),
  OPT_END(),
};

static struct _err_inj_drs_ecc_params {
  u32 ch_id;
  u32 duration;
  u32 inj_mode;
  u32 tag;
  bool verbose;
} err_inj_drs_ecc_params;


#define ERR_INJ_DRS_ECC_OPTIONS() \
OPT_UINTEGER('c', "ch_id", &err_inj_drs_ecc_params.ch_id, "DRS channel"), \
OPT_UINTEGER('d', "duration", &err_inj_drs_ecc_params.duration, "Duration"), \
OPT_UINTEGER('i', "inj_mode", &err_inj_drs_ecc_params.inj_mode, "Injection mode"), \
OPT_UINTEGER('t', "tag", &err_inj_drs_ecc_params.tag, "Tag")

static const struct option cmd_err_inj_drs_ecc_options[] = {
  BASE_OPTIONS(),
  ERR_INJ_DRS_ECC_OPTIONS(),
  OPT_END(),
};

static struct _err_inj_rxflit_crc_params {
  u32 cxl_mem_id;
  bool verbose;
} err_inj_rxflit_crc_params;


#define ERR_INJ_RXFLIT_CRC_OPTIONS() \
OPT_UINTEGER('c', "cxl_mem_id", &err_inj_rxflit_crc_params.cxl_mem_id, "CXL.mem instance")

static const struct option cmd_err_inj_rxflit_crc_options[] = {
  BASE_OPTIONS(),
  ERR_INJ_RXFLIT_CRC_OPTIONS(),
  OPT_END(),
};

static struct _err_inj_txflit_crc_params {
  u32 cxl_mem_id;
  bool verbose;
} err_inj_txflit_crc_params;


#define ERR_INJ_TXFLIT_CRC_OPTIONS() \
OPT_UINTEGER('c', "cxl_mem_id", &err_inj_txflit_crc_params.cxl_mem_id, "CXL.mem instance")

static const struct option cmd_err_inj_txflit_crc_options[] = {
  BASE_OPTIONS(),
  ERR_INJ_TXFLIT_CRC_OPTIONS(),
  OPT_END(),
};

static struct _err_inj_viral_params {
  u32 ld_id;
  bool verbose;
} err_inj_viral_params;


#define ERR_INJ_VIRAL_OPTIONS() \
OPT_UINTEGER('l', "ld_id", &err_inj_viral_params.ld_id, "ld_id")

static const struct option cmd_err_inj_viral_options[] = {
  BASE_OPTIONS(),
  ERR_INJ_VIRAL_OPTIONS(),
  OPT_END(),
};

static struct _eh_eye_cap_run_params {
  u32 depth;
  u32 lane_mask;
  bool verbose;
} eh_eye_cap_run_params;


#define EH_EYE_CAP_RUN_OPTIONS() \
OPT_UINTEGER('d', "depth", &eh_eye_cap_run_params.depth, "capture depth (BT_DEPTH_MIN to BT_DEPTH_MAX)"), \
OPT_UINTEGER('l', "lane_mask", &eh_eye_cap_run_params.lane_mask, "lane mask")

static const struct option cmd_eh_eye_cap_run_options[] = {
  BASE_OPTIONS(),
  EH_EYE_CAP_RUN_OPTIONS(),
  OPT_END(),
};

static struct _eh_eye_cap_read_params {
  u32 lane_id;
  u32 bin_num;
  bool verbose;
} eh_eye_cap_read_params;


#define EH_EYE_CAP_READ_OPTIONS() \
OPT_UINTEGER('l', "lane_id", &eh_eye_cap_read_params.lane_id, "lane ID"), \
OPT_UINTEGER('b', "bin_num", &eh_eye_cap_read_params.bin_num, "bin number [0 .. BT_BIN_TOT - 1]")

static const struct option cmd_eh_eye_cap_read_options[] = {
  BASE_OPTIONS(),
  EH_EYE_CAP_READ_OPTIONS(),
  OPT_END(),
};

static struct _eh_eye_cap_timeout_enable_params {
  u32 enable;
  bool verbose;
} eh_eye_cap_timeout_enable_params;

#define EH_EYE_CAP_TIMEOUT_ENABLE_BASE_OPTIONS() \
OPT_BOOLEAN('v',"verbose", &eh_eye_cap_timeout_enable_params.verbose, "turn on debug")

#define EH_EYE_CAP_TIMEOUT_ENABLE_OPTIONS() \
OPT_UINTEGER('e', "enable", &eh_eye_cap_timeout_enable_params.enable, "enable (0: Disable, 1: Enable)")

static const struct option cmd_eh_eye_cap_timeout_enable_options[] = {
  EH_EYE_CAP_TIMEOUT_ENABLE_BASE_OPTIONS(),
  EH_EYE_CAP_TIMEOUT_ENABLE_OPTIONS(),
  OPT_END(),
};

static struct _eh_eye_cap_status_params {
  bool verbose;
} eh_eye_cap_status_params;

#define EH_EYE_CAP_STATUS_BASE_OPTIONS() \
OPT_BOOLEAN('v',"verbose", &eh_eye_cap_status_params.verbose, "turn on debug")

static const struct option cmd_eh_eye_cap_status_options[] = {
  EH_EYE_CAP_STATUS_BASE_OPTIONS(),
  OPT_END(),
};

static struct _eh_adapt_get_params {
  u32 lane_id;
  bool verbose;
} eh_adapt_get_params;


#define EH_ADAPT_GET_OPTIONS() \
OPT_UINTEGER('l', "lane_id", &eh_adapt_get_params.lane_id, "lane id")

static const struct option cmd_eh_adapt_get_options[] = {
  BASE_OPTIONS(),
  EH_ADAPT_GET_OPTIONS(),
  OPT_END(),
};

static struct _eh_adapt_oneoff_params {
  u32 lane_id;
  u32 preload;
  u32 loops;
  u32 objects;
  bool verbose;
} eh_adapt_oneoff_params;


#define EH_ADAPT_ONEOFF_OPTIONS() \
OPT_UINTEGER('l', "lane_id", &eh_adapt_oneoff_params.lane_id, "lane id"), \
OPT_UINTEGER('p', "preload", &eh_adapt_oneoff_params.preload, "Adaption objects preload enable"), \
OPT_UINTEGER('m', "loops", &eh_adapt_oneoff_params.loops, "Adaptions loop"), \
OPT_UINTEGER('o', "objects", &eh_adapt_oneoff_params.objects, "Adaption objects enable")

static const struct option cmd_eh_adapt_oneoff_options[] = {
  BASE_OPTIONS(),
  EH_ADAPT_ONEOFF_OPTIONS(),
  OPT_END(),
};

static struct _fbist_stopconfig_set_params {
	u32 fbist_id;
	u32 stop_on_wresp;
	u32 stop_on_rresp;
	u32 stop_on_rdataerr;
	bool verbose;
} fbist_stopconfig_set_params;

#define FBIST_STOPCONFIG_SET_BASE_OPTIONS() \
OPT_BOOLEAN('v',"verbose", &fbist_stopconfig_set_params.verbose, "turn on debug")

#define FBIST_STOPCONFIG_SET_OPTIONS() \
OPT_UINTEGER('f', "fbist_id", &fbist_stopconfig_set_params.fbist_id, "Flex BIST Instance"), \
OPT_UINTEGER('w', "stop_on_wresp", &fbist_stopconfig_set_params.stop_on_wresp, "Stop on Write Response"), \
OPT_UINTEGER('r', "stop_on_rresp", &fbist_stopconfig_set_params.stop_on_rresp, "Stop on Read Response"), \
OPT_UINTEGER('e', "stop_on_rdataerr", &fbist_stopconfig_set_params.stop_on_rdataerr, "Stop on Read Data Error")

static const struct option cmd_fbist_stopconfig_set_options[] = {
	FBIST_STOPCONFIG_SET_BASE_OPTIONS(),
	FBIST_STOPCONFIG_SET_OPTIONS(),
	OPT_END(),
};

static struct _fbist_cyclecount_set_params {
	u32 fbist_id;
	u32 txg_nr;
	u64 cyclecount;
	bool verbose;
} fbist_cyclecount_set_params;

#define FBIST_CYCLECOUNT_SET_BASE_OPTIONS() \
OPT_BOOLEAN('v',"verbose", &fbist_cyclecount_set_params.verbose, "turn on debug")

#define FBIST_CYCLECOUNT_SET_OPTIONS() \
OPT_UINTEGER('f', "fbist_id", &fbist_cyclecount_set_params.fbist_id, "Flex BIST Instance"), \
OPT_UINTEGER('t', "txg_nr", &fbist_cyclecount_set_params.txg_nr, "TXG Nr"), \
OPT_U64('c', "cyclecount", &fbist_cyclecount_set_params.cyclecount, "cyclecount")

static const struct option cmd_fbist_cyclecount_set_options[] = {
	FBIST_CYCLECOUNT_SET_BASE_OPTIONS(),
	FBIST_CYCLECOUNT_SET_OPTIONS(),
	OPT_END(),
};

static struct _fbist_reset_set_params {
	u32 fbist_id;
	u32 txg0_reset;
	u32 txg1_reset;
	bool verbose;
} fbist_reset_set_params;

#define FBIST_RESET_SET_BASE_OPTIONS() \
OPT_BOOLEAN('v',"verbose", &fbist_reset_set_params.verbose, "turn on debug")

#define FBIST_RESET_SET_OPTIONS() \
OPT_UINTEGER('f', "fbist_id", &fbist_reset_set_params.fbist_id, "Flex BIST Instance"), \
OPT_UINTEGER('t', "txg0_reset", &fbist_reset_set_params.txg0_reset, "TXG0 Reset"), \
OPT_UINTEGER('u', "txg1_reset", &fbist_reset_set_params.txg1_reset, "TXG1 Reset")

static const struct option cmd_fbist_reset_set_options[] = {
	FBIST_RESET_SET_BASE_OPTIONS(),
	FBIST_RESET_SET_OPTIONS(),
	OPT_END(),
};

static struct _fbist_run_set_params {
	u32 fbist_id;
	u32 txg0_run;
	u32 txg1_run;
	bool verbose;
} fbist_run_set_params;

#define FBIST_RUN_SET_BASE_OPTIONS() \
OPT_BOOLEAN('v',"verbose", &fbist_run_set_params.verbose, "turn on debug")

#define FBIST_RUN_SET_OPTIONS() \
OPT_UINTEGER('f', "fbist_id", &fbist_run_set_params.fbist_id, "Flex BIST Instance"), \
OPT_UINTEGER('t', "txg0_run", &fbist_run_set_params.txg0_run, "TXG0 Run"), \
OPT_UINTEGER('u', "txg1_run", &fbist_run_set_params.txg1_run, "TXG1 Run")

static const struct option cmd_fbist_run_set_options[] = {
	FBIST_RUN_SET_BASE_OPTIONS(),
	FBIST_RUN_SET_OPTIONS(),
	OPT_END(),
};

static struct _fbist_run_get_params {
	u32 fbist_id;
	bool verbose;
} fbist_run_get_params;

#define FBIST_RUN_GET_BASE_OPTIONS() \
OPT_BOOLEAN('v',"verbose", &fbist_run_get_params.verbose, "turn on debug")

#define FBIST_RUN_GET_OPTIONS() \
OPT_UINTEGER('f', "fbist_id", &fbist_run_get_params.fbist_id, "Flex BIST Instance")

static const struct option cmd_fbist_run_get_options[] = {
	FBIST_RUN_GET_BASE_OPTIONS(),
	FBIST_RUN_GET_OPTIONS(),
	OPT_END(),
};

static struct _fbist_xfer_rem_cnt_get_params {
	u32 fbist_id;
	u32 thread_nr;
	bool verbose;
} fbist_xfer_rem_cnt_get_params;

#define FBIST_XFER_REM_CNT_GET_BASE_OPTIONS() \
OPT_BOOLEAN('v',"verbose", &fbist_xfer_rem_cnt_get_params.verbose, "turn on debug")

#define FBIST_XFER_REM_CNT_GET_OPTIONS() \
OPT_UINTEGER('f', "fbist_id", &fbist_xfer_rem_cnt_get_params.fbist_id, "Flex BIST Instance"), \
OPT_UINTEGER('t', "thread_nr", &fbist_xfer_rem_cnt_get_params.thread_nr, "Thread Nr")

static const struct option cmd_fbist_xfer_rem_cnt_get_options[] = {
	FBIST_XFER_REM_CNT_GET_BASE_OPTIONS(),
	FBIST_XFER_REM_CNT_GET_OPTIONS(),
	OPT_END(),
};

static struct _fbist_last_exp_read_data_get_params {
	u32 fbist_id;
	bool verbose;
} fbist_last_exp_read_data_get_params;

#define FBIST_LAST_EXP_READ_DATA_GET_BASE_OPTIONS() \
OPT_BOOLEAN('v',"verbose", &fbist_last_exp_read_data_get_params.verbose, "turn on debug")

#define FBIST_LAST_EXP_READ_DATA_GET_OPTIONS() \
OPT_UINTEGER('f', "fbist_id", &fbist_last_exp_read_data_get_params.fbist_id, "Flex BIST Instance")

static const struct option cmd_fbist_last_exp_read_data_get_options[] = {
	FBIST_LAST_EXP_READ_DATA_GET_BASE_OPTIONS(),
	FBIST_LAST_EXP_READ_DATA_GET_OPTIONS(),
	OPT_END(),
};

static struct _fbist_curr_cycle_cnt_get_params {
	u32 fbist_id;
	u32 txg_nr;
	bool verbose;
} fbist_curr_cycle_cnt_get_params;

#define FBIST_CURR_CYCLE_CNT_GET_BASE_OPTIONS() \
OPT_BOOLEAN('v',"verbose", &fbist_curr_cycle_cnt_get_params.verbose, "turn on debug")

#define FBIST_CURR_CYCLE_CNT_GET_OPTIONS() \
OPT_UINTEGER('f', "fbist_id", &fbist_curr_cycle_cnt_get_params.fbist_id, "Flex BIST Instance"), \
OPT_UINTEGER('t', "txg_nr", &fbist_curr_cycle_cnt_get_params.txg_nr, "TXG Nr")

static const struct option cmd_fbist_curr_cycle_cnt_get_options[] = {
	FBIST_CURR_CYCLE_CNT_GET_BASE_OPTIONS(),
	FBIST_CURR_CYCLE_CNT_GET_OPTIONS(),
	OPT_END(),
};

static struct _fbist_thread_status_get_params {
	u32 fbist_id;
	u32 txg_nr;
	u32 thread_nr;
	bool verbose;
} fbist_thread_status_get_params;

#define FBIST_THREAD_STATUS_GET_BASE_OPTIONS() \
OPT_BOOLEAN('v',"verbose", &fbist_thread_status_get_params.verbose, "turn on debug")

#define FBIST_THREAD_STATUS_GET_OPTIONS() \
OPT_UINTEGER('f', "fbist_id", &fbist_thread_status_get_params.fbist_id, "Flex BIST Instance"), \
OPT_UINTEGER('t', "txg_nr", &fbist_thread_status_get_params.txg_nr, "TXG Nr"), \
OPT_UINTEGER('u', "thread_nr", &fbist_thread_status_get_params.thread_nr, "Thread Nr")

static const struct option cmd_fbist_thread_status_get_options[] = {
	FBIST_THREAD_STATUS_GET_BASE_OPTIONS(),
	FBIST_THREAD_STATUS_GET_OPTIONS(),
	OPT_END(),
};

static struct _fbist_thread_trans_cnt_get_params {
	u32 fbist_id;
	u32 txg_nr;
	u32 thread_nr;
	bool verbose;
} fbist_thread_trans_cnt_get_params;

#define FBIST_THREAD_TRANS_CNT_GET_BASE_OPTIONS() \
OPT_BOOLEAN('v',"verbose", &fbist_thread_trans_cnt_get_params.verbose, "turn on debug")

#define FBIST_THREAD_TRANS_CNT_GET_OPTIONS() \
OPT_UINTEGER('f', "fbist_id", &fbist_thread_trans_cnt_get_params.fbist_id, "Flex BIST Instance"), \
OPT_UINTEGER('t', "txg_nr", &fbist_thread_trans_cnt_get_params.txg_nr, "TXG Nr"), \
OPT_UINTEGER('u', "thread_nr", &fbist_thread_trans_cnt_get_params.thread_nr, "Thread Nr")

static const struct option cmd_fbist_thread_trans_cnt_get_options[] = {
	FBIST_THREAD_TRANS_CNT_GET_BASE_OPTIONS(),
	FBIST_THREAD_TRANS_CNT_GET_OPTIONS(),
	OPT_END(),
};

static struct _fbist_thread_bandwidth_get_params {
	u32 fbist_id;
	u32 txg_nr;
	u32 thread_nr;
	bool verbose;
} fbist_thread_bandwidth_get_params;

#define FBIST_THREAD_BANDWIDTH_GET_BASE_OPTIONS() \
OPT_BOOLEAN('v',"verbose", &fbist_thread_bandwidth_get_params.verbose, "turn on debug")

#define FBIST_THREAD_BANDWIDTH_GET_OPTIONS() \
OPT_UINTEGER('f', "fbist_id", &fbist_thread_bandwidth_get_params.fbist_id, "Flex BIST Instance"), \
OPT_UINTEGER('t', "txg_nr", &fbist_thread_bandwidth_get_params.txg_nr, "TXG Nr"), \
OPT_UINTEGER('u', "thread_nr", &fbist_thread_bandwidth_get_params.thread_nr, "Thread Nr")

static const struct option cmd_fbist_thread_bandwidth_get_options[] = {
	FBIST_THREAD_BANDWIDTH_GET_BASE_OPTIONS(),
	FBIST_THREAD_BANDWIDTH_GET_OPTIONS(),
	OPT_END(),
};

static struct _fbist_thread_latency_get_params {
	u32 fbist_id;
	u32 txg_nr;
	u32 thread_nr;
	bool verbose;
} fbist_thread_latency_get_params;

#define FBIST_THREAD_LATENCY_GET_BASE_OPTIONS() \
OPT_BOOLEAN('v',"verbose", &fbist_thread_latency_get_params.verbose, "turn on debug")

#define FBIST_THREAD_LATENCY_GET_OPTIONS() \
OPT_UINTEGER('f', "fbist_id", &fbist_thread_latency_get_params.fbist_id, "Flex BIST Instance"), \
OPT_UINTEGER('t', "txg_nr", &fbist_thread_latency_get_params.txg_nr, "TXG Nr"), \
OPT_UINTEGER('u', "thread_nr", &fbist_thread_latency_get_params.thread_nr, "Thread Nr")

static const struct option cmd_fbist_thread_latency_get_options[] = {
	FBIST_THREAD_LATENCY_GET_BASE_OPTIONS(),
	FBIST_THREAD_LATENCY_GET_OPTIONS(),
	OPT_END(),
};

static struct _fbist_thread_perf_mon_set_params {
	u32 fbist_id;
	u32 txg_nr;
	u32 thread_nr;
	u32 pmon_preset_en;
	u32 pmon_clear_en;
	u32 pmon_rollover;
	u32 pmon_thread_lclk;
	bool verbose;
} fbist_thread_perf_mon_set_params;

#define FBIST_THREAD_PERF_MON_SET_BASE_OPTIONS() \
OPT_BOOLEAN('v',"verbose", &fbist_thread_perf_mon_set_params.verbose, "turn on debug")

#define FBIST_THREAD_PERF_MON_SET_OPTIONS() \
OPT_UINTEGER('f', "fbist_id", &fbist_thread_perf_mon_set_params.fbist_id, "Flex BIST Instance"), \
OPT_UINTEGER('t', "txg_nr", &fbist_thread_perf_mon_set_params.txg_nr, "TXG Nr"), \
OPT_UINTEGER('u', "thread_nr", &fbist_thread_perf_mon_set_params.thread_nr, "Thread Nr"), \
OPT_UINTEGER('p', "pmon_preset_en", &fbist_thread_perf_mon_set_params.pmon_preset_en, "Performance Monitor Preset Enable"), \
OPT_UINTEGER('c', "pmon_clear_en", &fbist_thread_perf_mon_set_params.pmon_clear_en, "Performance Monitor Clear Enable"), \
OPT_UINTEGER('r', "pmon_rollover", &fbist_thread_perf_mon_set_params.pmon_rollover, "Performance Monitor Rollover"), \
OPT_UINTEGER('l', "pmon_thread_lclk", &fbist_thread_perf_mon_set_params.pmon_thread_lclk, "Performance Monitor Thread lclk")

static const struct option cmd_fbist_thread_perf_mon_set_options[] = {
	FBIST_THREAD_PERF_MON_SET_BASE_OPTIONS(),
	FBIST_THREAD_PERF_MON_SET_OPTIONS(),
	OPT_END(),
};

static struct _fbist_top_read_status0_get_params {
	u32 fbist_id;
	bool verbose;
} fbist_top_read_status0_get_params;

#define FBIST_TOP_READ_STATUS0_GET_BASE_OPTIONS() \
OPT_BOOLEAN('v',"verbose", &fbist_top_read_status0_get_params.verbose, "turn on debug")

#define FBIST_TOP_READ_STATUS0_GET_OPTIONS() \
OPT_UINTEGER('f', "fbist_id", &fbist_top_read_status0_get_params.fbist_id, "Flex BIST Instance")

static const struct option cmd_fbist_top_read_status0_get_options[] = {
	FBIST_TOP_READ_STATUS0_GET_BASE_OPTIONS(),
	FBIST_TOP_READ_STATUS0_GET_OPTIONS(),
	OPT_END(),
};

static struct _fbist_top_err_cnt_get_params {
	u32 fbist_id;
	bool verbose;
} fbist_top_err_cnt_get_params;

#define FBIST_TOP_ERR_CNT_GET_BASE_OPTIONS() \
OPT_BOOLEAN('v',"verbose", &fbist_top_err_cnt_get_params.verbose, "turn on debug")

#define FBIST_TOP_ERR_CNT_GET_OPTIONS() \
OPT_UINTEGER('f', "fbist_id", &fbist_top_err_cnt_get_params.fbist_id, "Flex BIST Instance")

static const struct option cmd_fbist_top_err_cnt_get_options[] = {
	FBIST_TOP_ERR_CNT_GET_BASE_OPTIONS(),
	FBIST_TOP_ERR_CNT_GET_OPTIONS(),
	OPT_END(),
};

static struct _fbist_last_read_addr_get_params {
	u32 fbist_id;
	bool verbose;
} fbist_last_read_addr_get_params;

#define FBIST_LAST_READ_ADDR_GET_BASE_OPTIONS() \
OPT_BOOLEAN('v',"verbose", &fbist_last_read_addr_get_params.verbose, "turn on debug")

#define FBIST_LAST_READ_ADDR_GET_OPTIONS() \
OPT_UINTEGER('f', "fbist_id", &fbist_last_read_addr_get_params.fbist_id, "Flex BIST Instance")

static const struct option cmd_fbist_last_read_addr_get_options[] = {
	FBIST_LAST_READ_ADDR_GET_BASE_OPTIONS(),
	FBIST_LAST_READ_ADDR_GET_OPTIONS(),
	OPT_END(),
};

static struct _fbist_test_simpledata_params {
	u32 fbist_id;
	u32 test_nr;
	u64 start_address;
	u64 num_bytes;
	bool verbose;
} fbist_test_simpledata_params;

#define FBIST_TEST_SIMPLEDATA_BASE_OPTIONS() \
OPT_BOOLEAN('v',"verbose", &fbist_test_simpledata_params.verbose, "turn on debug")

#define FBIST_TEST_SIMPLEDATA_OPTIONS() \
OPT_UINTEGER('f', "fbist_id", &fbist_test_simpledata_params.fbist_id, "Flex BIST Instance"), \
OPT_UINTEGER('t', "test_nr", &fbist_test_simpledata_params.test_nr, "Test number to be setup"), \
OPT_U64('s', "start_address", &fbist_test_simpledata_params.start_address, "Start Address"), \
OPT_U64('n', "num_bytes", &fbist_test_simpledata_params.num_bytes, "Size of memory to operate on")

static const struct option cmd_fbist_test_simpledata_options[] = {
	FBIST_TEST_SIMPLEDATA_BASE_OPTIONS(),
	FBIST_TEST_SIMPLEDATA_OPTIONS(),
	OPT_END(),
};

static struct _fbist_test_addresstest_params {
	u32 fbist_id;
	u32 test_nr;
	u64 start_address;
	u64 num_bytes;
	u32 seed;
	bool verbose;
} fbist_test_addresstest_params;

#define FBIST_TEST_ADDRESSTEST_BASE_OPTIONS() \
OPT_BOOLEAN('v',"verbose", &fbist_test_addresstest_params.verbose, "turn on debug")

#define FBIST_TEST_ADDRESSTEST_OPTIONS() \
OPT_UINTEGER('f', "fbist_id", &fbist_test_addresstest_params.fbist_id, "Flex BIST Instance"), \
OPT_UINTEGER('t', "test_nr", &fbist_test_addresstest_params.test_nr, "Test number to be setup"), \
OPT_U64('a', "start_address", &fbist_test_addresstest_params.start_address, "Start Address"), \
OPT_U64('n', "num_bytes", &fbist_test_addresstest_params.num_bytes, "Size of memory to operate on"), \
OPT_UINTEGER('s', "seed", &fbist_test_addresstest_params.seed, "Inital Seed")

static const struct option cmd_fbist_test_addresstest_options[] = {
	FBIST_TEST_ADDRESSTEST_BASE_OPTIONS(),
	FBIST_TEST_ADDRESSTEST_OPTIONS(),
	OPT_END(),
};

static struct _fbist_test_movinginversion_params {
	u32 fbist_id;
	u32 test_nr;
	u32 phase_nr;
	u64 start_address;
	u64 num_bytes;
	u32 ddrpage_size;
	bool verbose;
} fbist_test_movinginversion_params;

#define FBIST_TEST_MOVINGINVERSION_BASE_OPTIONS() \
OPT_BOOLEAN('v',"verbose", &fbist_test_movinginversion_params.verbose, "turn on debug")

#define FBIST_TEST_MOVINGINVERSION_OPTIONS() \
OPT_UINTEGER('f', "fbist_id", &fbist_test_movinginversion_params.fbist_id, "Flex BIST Instance"), \
OPT_UINTEGER('t', "test_nr", &fbist_test_movinginversion_params.test_nr, "Test number to be setup"), \
OPT_UINTEGER('p', "phase_nr", &fbist_test_movinginversion_params.phase_nr, "Testphase to be setup"), \
OPT_U64('s', "start_address", &fbist_test_movinginversion_params.start_address, "Start Address"), \
OPT_U64('n', "num_bytes", &fbist_test_movinginversion_params.num_bytes, "Size of memory to operate on"), \
OPT_UINTEGER('d', "ddrpage_size", &fbist_test_movinginversion_params.ddrpage_size, "DDR Page size")

static const struct option cmd_fbist_test_movinginversion_options[] = {
	FBIST_TEST_MOVINGINVERSION_BASE_OPTIONS(),
	FBIST_TEST_MOVINGINVERSION_OPTIONS(),
	OPT_END(),
};

static struct _fbist_test_randomsequence_params {
	u32 fbist_id;
	u32 phase_nr;
	u64 start_address;
	u64 num_bytes;
	u32 ddrpage_size;
	u32 seed_dr0;
	u32 seed_dr1;
	bool verbose;
} fbist_test_randomsequence_params;

#define FBIST_TEST_RANDOMSEQUENCE_BASE_OPTIONS() \
OPT_BOOLEAN('v',"verbose", &fbist_test_randomsequence_params.verbose, "turn on debug")

#define FBIST_TEST_RANDOMSEQUENCE_OPTIONS() \
OPT_UINTEGER('f', "fbist_id", &fbist_test_randomsequence_params.fbist_id, "Flex BIST Instance"), \
OPT_UINTEGER('p', "phase_nr", &fbist_test_randomsequence_params.phase_nr, "Testphase to be setup"), \
OPT_U64('s', "start_address", &fbist_test_randomsequence_params.start_address, "Start Address"), \
OPT_U64('n', "num_bytes", &fbist_test_randomsequence_params.num_bytes, "Size of memory to operate on"), \
OPT_UINTEGER('d', "ddrpage_size", &fbist_test_randomsequence_params.ddrpage_size, "DDR Page size"), \
OPT_UINTEGER('t', "seed_dr0", &fbist_test_randomsequence_params.seed_dr0, "Seed_DR0"), \
OPT_UINTEGER('u', "seed_dr1", &fbist_test_randomsequence_params.seed_dr1, "Seed DR1")

static const struct option cmd_fbist_test_randomsequence_options[] = {
	FBIST_TEST_RANDOMSEQUENCE_BASE_OPTIONS(),
	FBIST_TEST_RANDOMSEQUENCE_OPTIONS(),
	OPT_END(),
};

static struct _eh_adapt_force_params {
  u32 lane_id;
  u32 rate;
  u32 vdd_bias;
  u32 ssc;
  u32 pga_gain;
  u32 pga_a0;
  u32 pga_off;
  u32 cdfe_a2;
  u32 cdfe_a3;
  u32 cdfe_a4;
  u32 cdfe_a5;
  u32 cdfe_a6;
  u32 cdfe_a7;
  u32 cdfe_a8;
  u32 cdfe_a9;
  u32 cdfe_a10;
  u32 dc_offset;
  u32 zobel_dc_offset;
  u32 udfe_thr_0;
  u32 udfe_thr_1;
  u32 median_amp;
  u32 zobel_a_gain;
  u32 ph_ofs_t;
  bool verbose;
} eh_adapt_force_params;


#define EH_ADAPT_FORCE_OPTIONS() \
OPT_UINTEGER('l', "lane_id", &eh_adapt_force_params.lane_id, "lane id"), \
OPT_UINTEGER('r', "rate", &eh_adapt_force_params.rate, "PCIe rate (0 - Gen1, 1 - Gen2, 2 - Gen3, 3 - Gen4, 4 - Gen5)"), \
OPT_UINTEGER('b', "vdd_bias", &eh_adapt_force_params.vdd_bias, "vdd bias (0 = 0.82V, 1 = 0.952V)"), \
OPT_UINTEGER('s', "ssc", &eh_adapt_force_params.ssc, "spread spectrum clocking enable (0 - SSC enable, 1 - SSC disable)"), \
OPT_UINTEGER('p', "pga_gain", &eh_adapt_force_params.pga_gain, "used to set the value of the PGA_GAIN object when preloading is enabled"), \
OPT_UINTEGER('q', "pga_a0", &eh_adapt_force_params.pga_a0, "used to set the value of the PGA_A0 object when preloading is enabled"), \
OPT_UINTEGER('t', "pga_off", &eh_adapt_force_params.pga_off, "PGA Stage1,2 offset preload value, split evenly between PGA Stage1 & Stage2 DC offset"), \
OPT_UINTEGER('c', "cdfe_a2", &eh_adapt_force_params.cdfe_a2, "used to set the value of CDFE_A2 (DFE Tap2) when preloading (CDFE_GRP0) is enabled"), \
OPT_UINTEGER('d', "cdfe_a3", &eh_adapt_force_params.cdfe_a3, "used to set the value of CDFE_A3 (DFE Tap3) when preloading (CDFE_GRP0) is enabled"), \
OPT_UINTEGER('e', "cdfe_a4", &eh_adapt_force_params.cdfe_a4, "used to set the value of CDFE_A4 (DFE Tap4) when preloading (CDFE_GRP0) is enabled"), \
OPT_UINTEGER('f', "cdfe_a5", &eh_adapt_force_params.cdfe_a5, "used to set the value of CDFE_A5 (DFE Tap5) when preloading (CDFE_GRP1) is enabled"), \
OPT_UINTEGER('g', "cdfe_a6", &eh_adapt_force_params.cdfe_a6, "used to set the value of CDFE_A6 (DFE Tap6) when preloading (CDFE_GRP1) is enabled"), \
OPT_UINTEGER('y', "cdfe_a7", &eh_adapt_force_params.cdfe_a7, "used to set the value of CDFE_A7 (DFE Tap7) when preloading (CDFE_GRP1) is enabled"), \
OPT_UINTEGER('i', "cdfe_a8", &eh_adapt_force_params.cdfe_a8, "used to set the value of CDFE_A8 (DFE Tap8) when preloading (CDFE_GRP2) is enabled"), \
OPT_UINTEGER('j', "cdfe_a9", &eh_adapt_force_params.cdfe_a9, "used to set the value of CDFE_A9 (DFE Tap9) when preloading (CDFE_GRP2) is enabled"), \
OPT_UINTEGER('k', "cdfe_a10", &eh_adapt_force_params.cdfe_a10, "used to set the value of CDFE_A10 (DFE Tap10) when preloading (CDFE_GRP2) is enabled"), \
OPT_UINTEGER('m', "dc_offset", &eh_adapt_force_params.dc_offset, "used to set the value of the DC_OFFSET object when preloading is enabled"), \
OPT_UINTEGER('z', "zobel_dc_offset", &eh_adapt_force_params.zobel_dc_offset, "Zobel DC offset preload value"), \
OPT_UINTEGER('u', "udfe_thr_0", &eh_adapt_force_params.udfe_thr_0, "used to set the value of the UDFE_THR_0 object when preloading is enabled"), \
OPT_UINTEGER('w', "udfe_thr_1", &eh_adapt_force_params.udfe_thr_1, "used to set the value of the UDFE_THR_1 object when preloading is enabled"), \
OPT_UINTEGER('n', "median_amp", &eh_adapt_force_params.median_amp, "used to set the value of the MEDIAN_AMP object when preloading is enabled"), \
OPT_UINTEGER('A', "zobel_a_gain", &eh_adapt_force_params.zobel_a_gain, "Zobel a_gain preload"), \
OPT_UINTEGER('x', "ph_ofs_t", &eh_adapt_force_params.ph_ofs_t, "Timing phase offset preload")

static const struct option cmd_eh_adapt_force_options[] = {
  BASE_OPTIONS(),
  EH_ADAPT_FORCE_OPTIONS(),
  OPT_END(),
};



static const struct option cmd_hbo_status_options[] = {
  BASE_OPTIONS(),
  OPT_END(),
};



static const struct option cmd_hbo_transfer_fw_options[] = {
  BASE_OPTIONS(),
  OPT_END(),
};



static const struct option cmd_hbo_activate_fw_options[] = {
  BASE_OPTIONS(),
  OPT_END(),
};

static struct _health_counters_clear_params {
  u32 bitmask;
  bool verbose;
} health_counters_clear_params;


#define HEALTH_COUNTERS_CLEAR_OPTIONS() \
OPT_UINTEGER('b', "bitmask", &health_counters_clear_params.bitmask, "health counters bitmask")

static const struct option cmd_health_counters_clear_options[] = {
  BASE_OPTIONS(),
  HEALTH_COUNTERS_CLEAR_OPTIONS(),
  OPT_END(),
};



static const struct option cmd_health_counters_get_options[] = {
  BASE_OPTIONS(),
  OPT_END(),
};



static const struct option cmd_hct_get_plat_param_options[] = {
  BASE_OPTIONS(),
  OPT_END(),
};

static struct _err_inj_hif_poison_params {
	u32 ch_id;
	u32 duration;
	u32 inj_mode;
	u64 address;
	bool verbose;
} err_inj_hif_poison_params;

#define ERR_INJ_HIF_POISON_BASE_OPTIONS() \
OPT_BOOLEAN('v',"verbose", &err_inj_hif_poison_params.verbose, "turn on debug")

#define ERR_INJ_HIF_POISON_OPTIONS() \
OPT_UINTEGER('c', "ch_id", &err_inj_hif_poison_params.ch_id, "HIF channel"), \
OPT_UINTEGER('d', "duration", &err_inj_hif_poison_params.duration, "Duration"), \
OPT_UINTEGER('i', "inj_mode", &err_inj_hif_poison_params.inj_mode, "Injection mode"), \
OPT_U64('a', "address", &err_inj_hif_poison_params.address, "Address")

static const struct option cmd_err_inj_hif_poison_options[] = {
	ERR_INJ_HIF_POISON_BASE_OPTIONS(),
	ERR_INJ_HIF_POISON_OPTIONS(),
	OPT_END(),
};

static struct _err_inj_hif_ecc_params {
	u32 ch_id;
	u32 duration;
	u32 inj_mode;
	u64 address;
	bool verbose;
} err_inj_hif_ecc_params;

#define ERR_INJ_HIF_ECC_BASE_OPTIONS() \
OPT_BOOLEAN('v',"verbose", &err_inj_hif_ecc_params.verbose, "turn on debug")

#define ERR_INJ_HIF_ECC_OPTIONS() \
OPT_UINTEGER('c', "ch_id", &err_inj_hif_ecc_params.ch_id, "HIF channel"), \
OPT_UINTEGER('d', "duration", &err_inj_hif_ecc_params.duration, "Duration"), \
OPT_UINTEGER('i', "inj_mode", &err_inj_hif_ecc_params.inj_mode, "Injection mode"), \
OPT_U64('a', "address", &err_inj_hif_ecc_params.address, "Address")

static const struct option cmd_err_inj_hif_ecc_options[] = {
	ERR_INJ_HIF_ECC_BASE_OPTIONS(),
	ERR_INJ_HIF_ECC_OPTIONS(),
	OPT_END(),
};

static struct _eh_link_dbg_cfg_params {
	u32 port_id;
	u32 op_mode;
	u32 cap_type;
	u32 lane_mask;
	u32 rate_mask;
	u32 timer_us;
	u32 cap_delay_us;
	u32 max_cap;
	bool verbose;
} eh_link_dbg_cfg_params;

#define EH_LINK_DBG_CFG_BASE_OPTIONS() \
OPT_BOOLEAN('v', "verbose", &eh_link_dbg_cfg_params.verbose, "turn on debug")

#define EH_LINK_DBG_CFG_OPTIONS() \
OPT_UINTEGER('p', "port_id", &eh_link_dbg_cfg_params.port_id, "Target Port"), \
OPT_UINTEGER('o', "op_mode", &eh_link_dbg_cfg_params.op_mode, "Operation Mode"), \
OPT_UINTEGER('c', "cap_type", &eh_link_dbg_cfg_params.cap_type, "Capture Type"), \
OPT_UINTEGER('l', "lane_mask", &eh_link_dbg_cfg_params.lane_mask, "Lane Mask"), \
OPT_UINTEGER('r', "rate_mask", &eh_link_dbg_cfg_params.rate_mask, "Rate Mask"), \
OPT_UINTEGER('t', "timer_us", &eh_link_dbg_cfg_params.timer_us, "Timer interval"), \
OPT_UINTEGER('d', "cap_delay_us", &eh_link_dbg_cfg_params.cap_delay_us, "Capture Timer delay"), \
OPT_UINTEGER('m', "max_cap", &eh_link_dbg_cfg_params.max_cap, "Max Capture")

static const struct option cmd_eh_link_dbg_cfg_options[] = {
	EH_LINK_DBG_CFG_BASE_OPTIONS(),
	EH_LINK_DBG_CFG_OPTIONS(),
	OPT_END(),
};

static struct _eh_link_dbg_entry_dump_params {
	u32 entry_idx;
	bool verbose;
} eh_link_dbg_entry_dump_params;

#define EH_LINK_DBG_ENTRY_DUMP_BASE_OPTIONS() \
OPT_BOOLEAN('v', "verbose", &eh_link_dbg_entry_dump_params.verbose, "turn on debug")

#define EH_LINK_DBG_ENTRY_DUMP_OPTIONS() \
OPT_UINTEGER('e', "entry_idx", &eh_link_dbg_entry_dump_params.entry_idx, "Entry Index")

static const struct option cmd_eh_link_dbg_entry_dump_options[] = {
	EH_LINK_DBG_ENTRY_DUMP_BASE_OPTIONS(),
	EH_LINK_DBG_ENTRY_DUMP_OPTIONS(),
	OPT_END(),
};

static struct _eh_link_dbg_lane_dump_params {
	u32 entry_idx;
	u32 lane_idx;
	bool verbose;
} eh_link_dbg_lane_dump_params;

#define EH_LINK_DBG_LANE_DUMP_BASE_OPTIONS() \
OPT_BOOLEAN('v', "verbose", &eh_link_dbg_lane_dump_params.verbose, "turn on debug")

#define EH_LINK_DBG_LANE_DUMP_OPTIONS() \
OPT_UINTEGER('e', "entry_idx", &eh_link_dbg_lane_dump_params.entry_idx, "Capture Entry Index"), \
OPT_UINTEGER('l', "lane_idx", &eh_link_dbg_lane_dump_params.lane_idx, "Capture Lane")

static const struct option cmd_eh_link_dbg_lane_dump_options[] = {
	EH_LINK_DBG_LANE_DUMP_BASE_OPTIONS(),
	EH_LINK_DBG_LANE_DUMP_OPTIONS(),
	OPT_END(),
};

static struct _eh_link_dbg_reset_params {
	bool verbose;
} eh_link_dbg_reset_params;

#define EH_LINK_DBG_RESET_BASE_OPTIONS() \
OPT_BOOLEAN('v', "verbose", &eh_link_dbg_reset_params.verbose, "turn on debug")

static const struct option cmd_eh_link_dbg_reset_options[] = {
	EH_LINK_DBG_RESET_BASE_OPTIONS(),
	OPT_END(),
};

static struct _conf_read_params {
	u32 offset;
	u32 length;
	bool verbose;
} conf_read_params;

#define CONF_READ_BASE_OPTIONS() \
OPT_BOOLEAN('v',"verbose", &conf_read_params.verbose, "turn on debug")

#define CONF_READ_OPTIONS() \
OPT_UINTEGER('o', "offset", &conf_read_params.offset, "Starting Offset"), \
OPT_UINTEGER('l', "length", &conf_read_params.length, "Requested Length")

static const struct option cmd_conf_read_options[] = {
	CONF_READ_BASE_OPTIONS(),
	CONF_READ_OPTIONS(),
	OPT_END(),
};

static struct _hct_get_config_params {
	u32 hct_inst;
	bool verbose;
} hct_get_config_params;

#define HCT_GET_CONFIG_BASE_OPTIONS() \
OPT_BOOLEAN('v',"verbose", &hct_get_config_params.verbose, "turn on debug")

#define HCT_GET_CONFIG_OPTIONS() \
OPT_UINTEGER('h', "hct_inst", &hct_get_config_params.hct_inst, "HCT Instance")

static const struct option cmd_hct_get_config_options[] = {
	HCT_GET_CONFIG_BASE_OPTIONS(),
	HCT_GET_CONFIG_OPTIONS(),
	OPT_END(),
};

static struct _hct_read_buffer_params {
	u32 hct_inst;
	u32 num_entries_to_read;
	bool verbose;
} hct_read_buffer_params;

#define HCT_READ_BUFFER_BASE_OPTIONS() \
OPT_BOOLEAN('v',"verbose", &hct_read_buffer_params.verbose, "turn on debug")

#define HCT_READ_BUFFER_OPTIONS() \
OPT_UINTEGER('h', "hct_inst", &hct_read_buffer_params.hct_inst, "HCT Instance"), \
OPT_UINTEGER('n', "num_entries_to_read", &hct_read_buffer_params.num_entries_to_read, "Number of buffer entries to read")

static const struct option cmd_hct_read_buffer_options[] = {
	HCT_READ_BUFFER_BASE_OPTIONS(),
	HCT_READ_BUFFER_OPTIONS(),
	OPT_END(),
};

static struct _hct_set_config_params {
	u32 hct_inst;
  u32 config_flags;
  u32 post_trig_depth;
  u32 ignore_valid;
  const char *trig_config_file;
	bool verbose;
} hct_set_config_params;

#define HCT_SET_CONFIG_BASE_OPTIONS() \
OPT_BOOLEAN('v',"verbose", &hct_set_config_params.verbose, "turn on debug")

#define HCT_SET_CONFIG_OPTIONS() \
OPT_UINTEGER('h', "hct_inst", &hct_set_config_params.hct_inst, "HCT Instance"), \
OPT_UINTEGER('c', "config_flags", &hct_set_config_params.config_flags, "Config Flags"), \
OPT_UINTEGER('p', "post_trig_depth", &hct_set_config_params.post_trig_depth, "Post Trigger Depth"), \
OPT_UINTEGER('i', "ignore_valid", &hct_set_config_params.ignore_valid, "Ignore Valid"), \
OPT_FILENAME('t', "trig_config_file", &hct_set_config_params.trig_config_file, "Trigger Config filepath", \
  "Filepath containing trigger config")

static const struct option cmd_hct_set_config_options[] = {
	HCT_SET_CONFIG_BASE_OPTIONS(),
	HCT_SET_CONFIG_OPTIONS(),
	OPT_END(),
};


static int action_cmd_clear_event_records(struct cxl_memdev *memdev, struct action_context *actx)
{
  u16 record_handle;
  if (cxl_memdev_is_active(memdev)) {
    fprintf(stderr, "%s: memdev active, abort clear_event_records\n",
      cxl_memdev_get_devname(memdev));
    return -EBUSY;
  }
  if (clear_event_records_params.clear_event_flags) {
    record_handle = 0;
    return cxl_memdev_clear_event_records(memdev, clear_event_records_params.event_log_type,
      clear_event_records_params.clear_event_flags, 0, &record_handle);
  }
  else {
    record_handle = (u16) clear_event_records_params.event_record_handle;
    return cxl_memdev_clear_event_records(memdev, clear_event_records_params.event_log_type,
      clear_event_records_params.clear_event_flags, 1, &record_handle);
  }
}

static int action_cmd_get_event_records(struct cxl_memdev *memdev, struct action_context *actx)
{
  if (cxl_memdev_is_active(memdev)) {
    fprintf(stderr, "%s: memdev active, abort get_event_records\n",
      cxl_memdev_get_devname(memdev));
    return -EBUSY;
  }
#if 0
  if (get_event_records_params.event_log_type < 0 || get_event_records_params.event_log_type > 3) {
    fprintf(stderr, "%s: Invalid Event Log type: %d, Allowed values Event log type "
      "(00 - information (default), 01 - warning, 02 - failure, 03 - fatal)\n",
      cxl_memdev_get_devname(memdev), get_event_records_params.event_log_type);
    return -EINVAL;
  }
#endif

  return cxl_memdev_get_event_records(memdev, get_event_records_params.event_log_type);
}

static int action_cmd_get_ld_info(struct cxl_memdev *memdev, struct action_context *actx)
{
  if (cxl_memdev_is_active(memdev)) {
    fprintf(stderr, "%s: memdev active, abort get_ld_info\n",
      cxl_memdev_get_devname(memdev));
    return -EBUSY;
  }

  return cxl_memdev_get_ld_info(memdev);
}

static int action_cmd_ddr_info(struct cxl_memdev *memdev, struct action_context *actx)
{
  if (cxl_memdev_is_active(memdev)) {
    fprintf(stderr, "%s: memdev active, abort ddr_info\n",
      cxl_memdev_get_devname(memdev));
    return -EBUSY;
  }
  fprintf(stdout, "memdev id: %d", cxl_memdev_get_id(memdev));
  return cxl_memdev_ddr_info(memdev, ddr_info_params.ddr_id);
}

static int action_cmd_get_health_info(struct cxl_memdev *memdev, struct action_context *actx)
{
  if (cxl_memdev_is_active(memdev)) {
    fprintf(stderr, "%s: memdev active, abort get_health_info\n",
      cxl_memdev_get_devname(memdev));
    return -EBUSY;
  }

  return cxl_memdev_get_health_info(memdev);
}

static int action_cmd_get_alert_config(struct cxl_memdev *memdev, struct action_context *actx)
{
  if (cxl_memdev_is_active(memdev)) {
    fprintf(stderr, "%s: memdev active, abort get_alert_config\n",
      cxl_memdev_get_devname(memdev));
    return -EBUSY;
  }

  return cxl_memdev_get_alert_config(memdev);
}

static int action_cmd_set_alert_config(struct cxl_memdev *memdev, struct action_context *actx)
{
  if (cxl_memdev_is_active(memdev)) {
    fprintf(stderr, "%s: memdev active, abort set_alert_config\n",
      cxl_memdev_get_devname(memdev));
    return -EBUSY;
  }

  return cxl_memdev_set_alert_config(memdev, alert_config_params.alert_prog_threshold,
    alert_config_params.device_temp_threshold, alert_config_params.mem_error_threshold);
}

static int action_cmd_get_timestamp(struct cxl_memdev *memdev, struct action_context *actx)
{
  if (cxl_memdev_is_active(memdev)) {
    fprintf(stderr, "%s: memdev active, get_timestamp\n",
      cxl_memdev_get_devname(memdev));
    return -EBUSY;
  }

  return cxl_memdev_get_timestamp(memdev);
}

static int action_cmd_set_timestamp(struct cxl_memdev *memdev, struct action_context *actx)
{
  if (cxl_memdev_is_active(memdev)) {
    fprintf(stderr, "%s: memdev active, set_timestamp\n",
      cxl_memdev_get_devname(memdev));
    return -EBUSY;
  }

  printf("timestamp: 0x%lx (%ld)\n", ts_params.timestamp, ts_params.timestamp);
  return cxl_memdev_set_timestamp(memdev, ts_params.timestamp);
}

#define INITIATE_TRANSFER 1
#define CONTINUE_TRANSFER 2
#define END_TRANSFER 3
#define ABORT_TRANSFER 4
const char *TRANSFER_FW_ERRORS[15] = {
  "Success",
  "Background Command Started",
  "Invalid Parameter",
  "Unsupported",
  "Internal Error",
  "Retry Required",
  "Busy",
  "Media Disabled",
  "FW Transfer in Progress",
  "FW Transfer Out of Order",
  "FW Authentication Failed",
  "Invalid Slot",
  "Aborted",
  "Invalid Security State",
  "Invalid Payload Length"
};

/*
 * Performs inband FW update through a series of successive calls to transfer-fw. The rom
 * is loaded into memory and transfered in 128*n byte chunks. transfer-fw supports several
 * actions that are specified as part of the input payload. The first call sets the action
 * to initiate_transfer and includes the first chunk. The remaining chunks are then sent
 * with the continue_transfer action. Finally, the end_transfer action will cause the
 * device to validate the binary and transfer it to the indicated slot.
 *
 * User must provide available FW slot as indicated from get-fw-info. This slot is provided
 * for every call to transfer-fw, but will only be read during the end_transfer call.
*/

struct cxl_ctx {
	/* log_ctx must be first member for cxl_set_log_fn compat */
	struct log_ctx ctx;
	int refcount;
	void *userdata;
	int memdevs_init;
	struct list_head memdevs;
	struct kmod_ctx *kmod_ctx;
	void *private_data;
};
static int action_cmd_update_fw(struct cxl_memdev *memdev, struct action_context *actx)
{
  struct stat fileStat;
  int filesize;
  FILE *rom;
  int rc;
  int fd;
  int num_blocks;
  int num_read;
  int size;
  const int max_retries = 10;
  int retry_count;
  u32 offset;
  fwblock *rom_buffer;
  u32 opcode;
  u8 action;
  int sleep_time = 1;
  int percent_to_print = 0;
  struct cxl_ctx *ctx = cxl_memdev_get_ctx(memdev);

  rom = fopen(update_fw_params.filepath, "rb");
  if (rom == NULL) {
    fprintf(stderr, "Error: File open returned %s\nCould not open file %s\n",
                  strerror(errno), update_fw_params.filepath);
    return -ENOENT;
  }

  if (cxl_memdev_is_active(memdev)) {
    fprintf(stderr, "%s: memdev active, set_timestamp\n",
      cxl_memdev_get_devname(memdev));
    return -EBUSY;
  }

  dbg(ctx, "Rom filepath: %s\n", update_fw_params.filepath);
  fd = fileno(rom);
  rc = fstat(fd, &fileStat);
  if (rc != 0) {
    dbg(ctx, "Could not read filesize");
    fclose(rom);
    return 1;
  }

  filesize = fileStat.st_size;
  dbg(ctx, "ROM size: %d bytes\n", filesize);

  num_blocks = filesize / FW_BLOCK_SIZE;
  if (filesize % FW_BLOCK_SIZE != 0)
  {
    num_blocks++;
  }

  rom_buffer = (fwblock*) malloc(filesize);
  num_read = fread(rom_buffer, 1, filesize, rom);
  if (filesize != num_read)
  {
    fprintf(stderr, "Number of bytes read: %d\nNumber of bytes expected: %d\n", num_read, num_blocks);
    free(rom_buffer);
    fclose(rom);
    return -ENOENT;
  }

  offset = 0;
  if (update_fw_params.hbo) {
    opcode = 0xCD01; // Pioneer vendor opcode for hbo-transfer-fw
  } else {
    opcode = 0x0201; // Spec defined transfer-fw
  }

  for (int i = 0; i < num_blocks; i++)
  {
    offset = i * (FW_BLOCK_SIZE / FW_BYTE_ALIGN);

    if ( (i *  100) / num_blocks >= percent_to_print)
    {
      printf("%d percent complete. Transfering block %d of %d at offset 0x%x\n", percent_to_print, i, num_blocks, offset);
      percent_to_print = percent_to_print + 10;
    }


        if (i == 0)
            action = INITIATE_TRANSFER;
        else if (i == num_blocks - 1)
            action = END_TRANSFER;
        else
            action = CONTINUE_TRANSFER;

        size = FW_BLOCK_SIZE;
        if (i == num_blocks - 1 && filesize % FW_BLOCK_SIZE != 0) {
            size = filesize % FW_BLOCK_SIZE;
        }

    fflush(stdout);
    rc = cxl_memdev_transfer_fw(memdev, action, update_fw_params.slot, offset, size, rom_buffer[i], opcode);

    retry_count = 0;
    sleep_time = 10;
    while (rc != 0)
    {
      if (retry_count > max_retries)
      {
        fprintf(stderr, "Maximum %d retries exceeded while transferring block %d\n", max_retries, i);
        goto abort;
      }
      dbg(ctx, "Mailbox returned %d: %s\nretrying in %d seconds...\n", rc, TRANSFER_FW_ERRORS[rc], sleep_time);
      sleep(sleep_time);
      rc = cxl_memdev_transfer_fw(memdev, action, update_fw_params.slot, offset, size, rom_buffer[i], opcode);
      retry_count++;
    }

    if (rc != 0)
    {
      fprintf(stderr, "transfer_fw failed on %d of %d\n", i, num_blocks);
      goto abort;
    }

    rc = cxl_memdev_hbo_status(memdev, 0);
    retry_count = 0;
    sleep_time = 10;
    while (rc != 0)
    {
      if (retry_count > max_retries)
      {
        dbg(ctx, "Maximum %d retries exceeded for hbo_status of block %d\n", max_retries, i);
        goto abort;
      }
      dbg(ctx, "HBO Status Mailbox returned %d: %s\nretrying in %d seconds...\n", rc, TRANSFER_FW_ERRORS[rc], sleep_time);
      sleep(sleep_time);
      rc = cxl_memdev_hbo_status(memdev, 0);
      retry_count++;
    }

    if (rc != 0)
    {
      fprintf(stderr, "transfer_fw failed on %d of %d\n", i, num_blocks);
      goto abort;
    }

    if (update_fw_params.mock)
    {
      goto abort;
    }
  }

  dbg(ctx, "Transfer completed successfully and fw was transferred to slot %d\n", update_fw_params.slot);
  goto out;
abort:
  sleep(2.0);
  rc = cxl_memdev_transfer_fw(memdev, ABORT_TRANSFER, update_fw_params.slot, FW_BLOCK_SIZE, FW_BLOCK_SIZE, rom_buffer[0], opcode);
  dbg(ctx, "Abort return status %d\n", rc);
out:
  free(rom_buffer);
  fclose(rom);
  return 0;
}

static int action_cmd_get_event_interrupt_policy(struct cxl_memdev *memdev, struct action_context *actx)
{
  if (cxl_memdev_is_active(memdev)) {
    fprintf(stderr, "%s: memdev active, get_event_interrupt_policy\n",
      cxl_memdev_get_devname(memdev));
    return -EBUSY;
  }

  return cxl_memdev_get_event_interrupt_policy(memdev);
}

static int action_cmd_set_event_interrupt_policy(struct cxl_memdev *memdev, struct action_context *actx)
{
  if (cxl_memdev_is_active(memdev)) {
    fprintf(stderr, "%s: memdev active, set_event_interrupt_policy\n",
      cxl_memdev_get_devname(memdev));
    return -EBUSY;
  }

  return cxl_memdev_set_event_interrupt_policy(memdev, interrupt_policy_params.policy);
}

static int action_cmd_get_cel_log(struct cxl_memdev *memdev, struct action_context *actx)
{
  if (cxl_memdev_is_active(memdev)) {
    fprintf(stderr, "%s: memdev active, get_cel_log\n",
      cxl_memdev_get_devname(memdev));
    return -EBUSY;
  }

  return cxl_memdev_get_cel_log(memdev);
}

static int action_cmd_get_supported_logs(struct cxl_memdev *memdev, struct action_context *actx)
{
  if (cxl_memdev_is_active(memdev)) {
    fprintf(stderr, "%s: memdev active, get_supported_logs\n",
      cxl_memdev_get_devname(memdev));
    return -EBUSY;
  }

  return cxl_memdev_get_supported_logs(memdev);
}

static int action_cmd_identify(struct cxl_memdev *memdev, struct action_context *actx)
{
  if (cxl_memdev_is_active(memdev)) {
    fprintf(stderr, "%s: memdev active, cmd_identify\n",
      cxl_memdev_get_devname(memdev));
    return -EBUSY;
  }

  return cxl_memdev_cmd_identify(memdev);
}

static int action_cmd_hct_start_stop_trigger(struct cxl_memdev *memdev, struct action_context *actx)
{
  if (cxl_memdev_is_active(memdev)) {
    fprintf(stderr, "%s: memdev active, abort hct_start_stop_trigger\n",
      cxl_memdev_get_devname(memdev));
    return -EBUSY;
  }

  return cxl_memdev_hct_start_stop_trigger(memdev, hct_start_stop_trigger_params.hct_inst,
    hct_start_stop_trigger_params.buf_control);
}

static int action_cmd_hct_get_buffer_status(struct cxl_memdev *memdev, struct action_context *actx)
{
  if (cxl_memdev_is_active(memdev)) {
    fprintf(stderr, "%s: memdev active, abort hct_get_buffer_status\n",
      cxl_memdev_get_devname(memdev));
    return -EBUSY;
  }

  return cxl_memdev_hct_get_buffer_status(memdev, hct_get_buffer_status_params.hct_inst);
}

static int action_cmd_hct_enable(struct cxl_memdev *memdev, struct action_context *actx)
{
  if (cxl_memdev_is_active(memdev)) {
    fprintf(stderr, "%s: memdev active, abort hct_enable\n",
      cxl_memdev_get_devname(memdev));
    return -EBUSY;
  }

  return cxl_memdev_hct_enable(memdev, hct_enable_params.hct_inst);
}

static int action_cmd_ltmon_capture_clear(struct cxl_memdev *memdev, struct action_context *actx)
{
  if (cxl_memdev_is_active(memdev)) {
    fprintf(stderr, "%s: memdev active, abort ltmon_capture_clear\n",
      cxl_memdev_get_devname(memdev));
    return -EBUSY;
  }

  return cxl_memdev_ltmon_capture_clear(memdev, ltmon_capture_clear_params.cxl_mem_id);
}

static int action_cmd_ltmon_capture(struct cxl_memdev *memdev, struct action_context *actx)
{
  if (cxl_memdev_is_active(memdev)) {
    fprintf(stderr, "%s: memdev active, abort ltmon_capture\n",
      cxl_memdev_get_devname(memdev));
    return -EBUSY;
  }

  return cxl_memdev_ltmon_capture(memdev, ltmon_capture_params.cxl_mem_id,
    ltmon_capture_params.capt_mode, ltmon_capture_params.ignore_sub_chg,
    ltmon_capture_params.ignore_rxl0_chg, ltmon_capture_params.trig_src_sel);
}

static int action_cmd_device_info_get(struct cxl_memdev *memdev, struct action_context *actx)
{
  if (cxl_memdev_is_active(memdev)) {
    fprintf(stderr, "%s: memdev active, abort device_info_get\n",
      cxl_memdev_get_devname(memdev));
    return -EBUSY;
  }

  return cxl_memdev_device_info_get(memdev);
}

static int action_cmd_get_fw_info(struct cxl_memdev *memdev, struct action_context *actx)
{
  if (cxl_memdev_is_active(memdev)) {
    fprintf(stderr, "%s: memdev active, abort get_fw_info",
      cxl_memdev_get_devname(memdev));
    return -EBUSY;
  }

  return cxl_memdev_get_fw_info(memdev);
}

static int action_cmd_activate_fw(struct cxl_memdev *memdev, struct action_context *actx)
{
    int rc;
    const int max_retries = 300;
  int retry_count;
  int sleep_time = 60;

  if (cxl_memdev_is_active(memdev)) {
    fprintf(stderr, "%s: memdev active, abort activate_fw",
      cxl_memdev_get_devname(memdev));
    return -EBUSY;
  }

    rc = cxl_memdev_activate_fw(memdev, activate_fw_params.action, activate_fw_params.slot);
    retry_count = 0;
  while (rc != 0) {
        if (retry_count > max_retries) {
            printf("Maximum %d retries exceeded while activating fw for slot %d\n", max_retries, activate_fw_params.slot);
            return rc;
    }
    printf("Mailbox returned %d: %s\nretrying in %d seconds...\n", rc, TRANSFER_FW_ERRORS[rc], sleep_time);
    sleep(sleep_time);
    rc = cxl_memdev_activate_fw(memdev, activate_fw_params.action, activate_fw_params.slot);
    retry_count++;
    }

    if (rc != 0) {
        fprintf(stderr, "activate_fw failed for slot %d, error %d: %s\n", activate_fw_params.slot, rc, TRANSFER_FW_ERRORS[rc]);
        return rc;
  }

    rc = cxl_memdev_hbo_status(memdev, 0);
    retry_count = 0;
  while (rc != 0) {
        if (retry_count > max_retries) {
            printf("Maximum %d retries exceeded for hbo_status\n", max_retries);
            return rc;
      }
        printf("HBO Status Mailbox returned %d: %s\nretrying in %d seconds...\n", rc, TRANSFER_FW_ERRORS[rc], sleep_time);
        sleep(sleep_time);
        rc = cxl_memdev_hbo_status(memdev, 0);
    retry_count++;
  }

  if (rc != 0) {
        fprintf(stderr, "activate_fw failed for slot %d\n", activate_fw_params.slot);
        return rc;
  }

  return rc;
}

static int action_cmd_ltmon_capture_freeze_and_restore(struct cxl_memdev *memdev, struct action_context *actx)
{
  if (cxl_memdev_is_active(memdev)) {
    fprintf(stderr, "%s: memdev active, abort ltmon_capture_freeze_and_restore\n",
      cxl_memdev_get_devname(memdev));
    return -EBUSY;
  }

  return cxl_memdev_ltmon_capture_freeze_and_restore(memdev, ltmon_capture_freeze_and_restore_params.cxl_mem_id,
    ltmon_capture_freeze_and_restore_params.freeze_restore);
}

static int action_cmd_ltmon_l2r_count_dump(struct cxl_memdev *memdev, struct action_context *actx)
{
  if (cxl_memdev_is_active(memdev)) {
    fprintf(stderr, "%s: memdev active, abort ltmon_l2r_count_dump\n",
      cxl_memdev_get_devname(memdev));
    return -EBUSY;
  }

  return cxl_memdev_ltmon_l2r_count_dump(memdev, ltmon_l2r_count_dump_params.cxl_mem_id);
}

static int action_cmd_ltmon_l2r_count_clear(struct cxl_memdev *memdev, struct action_context *actx)
{
  if (cxl_memdev_is_active(memdev)) {
    fprintf(stderr, "%s: memdev active, abort ltmon_l2r_count_clear\n",
      cxl_memdev_get_devname(memdev));
    return -EBUSY;
  }

  return cxl_memdev_ltmon_l2r_count_clear(memdev, ltmon_l2r_count_clear_params.cxl_mem_id);
}

static int action_cmd_ltmon_basic_cfg(struct cxl_memdev *memdev, struct action_context *actx)
{
  if (cxl_memdev_is_active(memdev)) {
    fprintf(stderr, "%s: memdev active, abort ltmon_basic_cfg\n",
      cxl_memdev_get_devname(memdev));
    return -EBUSY;
  }

  return cxl_memdev_ltmon_basic_cfg(memdev, ltmon_basic_cfg_params.cxl_mem_id,
    ltmon_basic_cfg_params.tick_cnt, ltmon_basic_cfg_params.global_ts);
}

static int action_cmd_ltmon_watch(struct cxl_memdev *memdev, struct action_context *actx)
{
  if (cxl_memdev_is_active(memdev)) {
    fprintf(stderr, "%s: memdev active, abort ltmon_watch\n",
      cxl_memdev_get_devname(memdev));
    return -EBUSY;
  }

  return cxl_memdev_ltmon_watch(memdev, ltmon_watch_params.cxl_mem_id,
    ltmon_watch_params.watch_id, ltmon_watch_params.watch_mode, ltmon_watch_params.src_maj_st,
    ltmon_watch_params.src_min_st, ltmon_watch_params.src_l0_st, ltmon_watch_params.dst_maj_st,
    ltmon_watch_params.dst_min_st, ltmon_watch_params.dst_l0_st);
}

static int action_cmd_ltmon_capture_stat(struct cxl_memdev *memdev, struct action_context *actx)
{
  if (cxl_memdev_is_active(memdev)) {
    fprintf(stderr, "%s: memdev active, abort ltmon_capture_stat\n",
      cxl_memdev_get_devname(memdev));
    return -EBUSY;
  }

  return cxl_memdev_ltmon_capture_stat(memdev, ltmon_capture_stat_params.cxl_mem_id);
}

static int action_cmd_ltmon_capture_log_dmp(struct cxl_memdev *memdev, struct action_context *actx)
{
  if (cxl_memdev_is_active(memdev)) {
    fprintf(stderr, "%s: memdev active, abort ltmon_capture_log_dmp\n",
      cxl_memdev_get_devname(memdev));
    return -EBUSY;
  }

  return cxl_memdev_ltmon_capture_log_dmp(memdev, ltmon_capture_log_dmp_params.cxl_mem_id,
    ltmon_capture_log_dmp_params.dump_idx, ltmon_capture_log_dmp_params.dump_cnt);
}

static int action_cmd_ltmon_capture_trigger(struct cxl_memdev *memdev, struct action_context *actx)
{
  if (cxl_memdev_is_active(memdev)) {
    fprintf(stderr, "%s: memdev active, abort ltmon_capture_trigger\n",
      cxl_memdev_get_devname(memdev));
    return -EBUSY;
  }

  return cxl_memdev_ltmon_capture_trigger(memdev, ltmon_capture_trigger_params.cxl_mem_id,
    ltmon_capture_trigger_params.trig_src);
}

static int action_cmd_ltmon_enable(struct cxl_memdev *memdev, struct action_context *actx)
{
  if (cxl_memdev_is_active(memdev)) {
    fprintf(stderr, "%s: memdev active, abort ltmon_enable\n",
      cxl_memdev_get_devname(memdev));
    return -EBUSY;
  }

  return cxl_memdev_ltmon_enable(memdev, ltmon_enable_params.cxl_mem_id,
    ltmon_enable_params.enable);
}

static int action_cmd_osa_os_type_trig_cfg(struct cxl_memdev *memdev, struct action_context *actx)
{
  if (cxl_memdev_is_active(memdev)) {
    fprintf(stderr, "%s: memdev active, abort osa_os_type_trig_cfg\n",
      cxl_memdev_get_devname(memdev));
    return -EBUSY;
  }

  return cxl_memdev_osa_os_type_trig_cfg(memdev, osa_os_type_trig_cfg_params.cxl_mem_id,
    osa_os_type_trig_cfg_params.lane_mask, osa_os_type_trig_cfg_params.lane_dir_mask,
    osa_os_type_trig_cfg_params.rate_mask, osa_os_type_trig_cfg_params.os_type_mask);
}

static int action_cmd_osa_cap_ctrl(struct cxl_memdev *memdev, struct action_context *actx)
{
  if (cxl_memdev_is_active(memdev)) {
    fprintf(stderr, "%s: memdev active, abort osa_cap_ctrl\n",
      cxl_memdev_get_devname(memdev));
    return -EBUSY;
  }

  return cxl_memdev_osa_cap_ctrl(memdev, osa_cap_ctrl_params.cxl_mem_id,
    osa_cap_ctrl_params.lane_mask, osa_cap_ctrl_params.lane_dir_mask,
    osa_cap_ctrl_params.drop_single_os, osa_cap_ctrl_params.stop_mode,
    osa_cap_ctrl_params.snapshot_mode, osa_cap_ctrl_params.post_trig_num,
    osa_cap_ctrl_params.os_type_mask);
}

static int action_cmd_osa_cfg_dump(struct cxl_memdev *memdev, struct action_context *actx)
{
  if (cxl_memdev_is_active(memdev)) {
    fprintf(stderr, "%s: memdev active, abort osa_cfg_dump\n",
      cxl_memdev_get_devname(memdev));
    return -EBUSY;
  }

  return cxl_memdev_osa_cfg_dump(memdev, osa_cfg_dump_params.cxl_mem_id);
}

static int action_cmd_osa_ana_op(struct cxl_memdev *memdev, struct action_context *actx)
{
  if (cxl_memdev_is_active(memdev)) {
    fprintf(stderr, "%s: memdev active, abort osa_ana_op\n",
      cxl_memdev_get_devname(memdev));
    return -EBUSY;
  }

  return cxl_memdev_osa_ana_op(memdev, osa_ana_op_params.cxl_mem_id,
    osa_ana_op_params.op);
}

static int action_cmd_osa_status_query(struct cxl_memdev *memdev, struct action_context *actx)
{
  if (cxl_memdev_is_active(memdev)) {
    fprintf(stderr, "%s: memdev active, abort osa_status_query\n",
      cxl_memdev_get_devname(memdev));
    return -EBUSY;
  }

  return cxl_memdev_osa_status_query(memdev, osa_status_query_params.cxl_mem_id);
}

static int action_cmd_osa_access_rel(struct cxl_memdev *memdev, struct action_context *actx)
{
  if (cxl_memdev_is_active(memdev)) {
    fprintf(stderr, "%s: memdev active, abort osa_access_rel\n",
      cxl_memdev_get_devname(memdev));
    return -EBUSY;
  }

  return cxl_memdev_osa_access_rel(memdev, osa_access_rel_params.cxl_mem_id);
}

static int action_cmd_perfcnt_mta_ltif_set(struct cxl_memdev *memdev, struct action_context *actx)
{
  if (cxl_memdev_is_active(memdev)) {
    fprintf(stderr, "%s: memdev active, abort perfcnt_mta_ltif_set\n",
      cxl_memdev_get_devname(memdev));
    return -EBUSY;
  }

  return cxl_memdev_perfcnt_mta_ltif_set(memdev, perfcnt_mta_ltif_set_params.counter,
    perfcnt_mta_ltif_set_params.match_value, perfcnt_mta_ltif_set_params.opcode,
    perfcnt_mta_ltif_set_params.meta_field, perfcnt_mta_ltif_set_params.meta_value);
}

static int action_cmd_perfcnt_mta_get(struct cxl_memdev *memdev, struct action_context *actx)
{
  if (cxl_memdev_is_active(memdev)) {
    fprintf(stderr, "%s: memdev active, abort perfcnt_mta_get\n",
      cxl_memdev_get_devname(memdev));
    return -EBUSY;
  }

  return cxl_memdev_perfcnt_mta_get(memdev, perfcnt_mta_get_params.type,
    perfcnt_mta_get_params.counter);
}

static int action_cmd_perfcnt_mta_latch_val_get(struct cxl_memdev *memdev, struct action_context *actx)
{
  if (cxl_memdev_is_active(memdev)) {
    fprintf(stderr, "%s: memdev active, abort perfcnt_mta_latch_val_get\n",
      cxl_memdev_get_devname(memdev));
    return -EBUSY;
  }

  return cxl_memdev_perfcnt_mta_latch_val_get(memdev, perfcnt_mta_latch_val_get_params.type,
    perfcnt_mta_latch_val_get_params.counter);
}

static int action_cmd_perfcnt_mta_counter_clear(struct cxl_memdev *memdev, struct action_context *actx)
{
  if (cxl_memdev_is_active(memdev)) {
    fprintf(stderr, "%s: memdev active, abort perfcnt_mta_counter_clear\n",
      cxl_memdev_get_devname(memdev));
    return -EBUSY;
  }

  return cxl_memdev_perfcnt_mta_counter_clear(memdev, perfcnt_mta_counter_clear_params.type,
    perfcnt_mta_counter_clear_params.counter);
}

static int action_cmd_perfcnt_mta_cnt_val_latch(struct cxl_memdev *memdev, struct action_context *actx)
{
  if (cxl_memdev_is_active(memdev)) {
    fprintf(stderr, "%s: memdev active, abort perfcnt_mta_cnt_val_latch\n",
      cxl_memdev_get_devname(memdev));
    return -EBUSY;
  }

  return cxl_memdev_perfcnt_mta_cnt_val_latch(memdev, perfcnt_mta_cnt_val_latch_params.type,
    perfcnt_mta_cnt_val_latch_params.counter);
}

static int action_cmd_perfcnt_mta_hif_set(struct cxl_memdev *memdev, struct action_context *actx)
{
  if (cxl_memdev_is_active(memdev)) {
    fprintf(stderr, "%s: memdev active, abort perfcnt_mta_hif_set\n",
      cxl_memdev_get_devname(memdev));
    return -EBUSY;
  }

  return cxl_memdev_perfcnt_mta_hif_set(memdev, perfcnt_mta_hif_set_params.counter,
    perfcnt_mta_hif_set_params.match_value, perfcnt_mta_hif_set_params.addr,
    perfcnt_mta_hif_set_params.req_ty, perfcnt_mta_hif_set_params.sc_ty);
}

static int action_cmd_perfcnt_mta_hif_cfg_get(struct cxl_memdev *memdev, struct action_context *actx)
{
  if (cxl_memdev_is_active(memdev)) {
    fprintf(stderr, "%s: memdev active, abort perfcnt_mta_hif_cfg_get\n",
      cxl_memdev_get_devname(memdev));
    return -EBUSY;
  }

  return cxl_memdev_perfcnt_mta_hif_cfg_get(memdev, perfcnt_mta_hif_cfg_get_params.counter);
}

static int action_cmd_perfcnt_mta_hif_latch_val_get(struct cxl_memdev *memdev, struct action_context *actx)
{
  if (cxl_memdev_is_active(memdev)) {
    fprintf(stderr, "%s: memdev active, abort perfcnt_mta_hif_latch_val_get\n",
      cxl_memdev_get_devname(memdev));
    return -EBUSY;
  }

  return cxl_memdev_perfcnt_mta_hif_latch_val_get(memdev, perfcnt_mta_hif_latch_val_get_params.counter);
}

static int action_cmd_perfcnt_mta_hif_counter_clear(struct cxl_memdev *memdev, struct action_context *actx)
{
  if (cxl_memdev_is_active(memdev)) {
    fprintf(stderr, "%s: memdev active, abort perfcnt_mta_hif_counter_clear\n",
      cxl_memdev_get_devname(memdev));
    return -EBUSY;
  }

  return cxl_memdev_perfcnt_mta_hif_counter_clear(memdev, perfcnt_mta_hif_counter_clear_params.counter);
}

static int action_cmd_perfcnt_mta_hif_cnt_val_latch(struct cxl_memdev *memdev, struct action_context *actx)
{
  if (cxl_memdev_is_active(memdev)) {
    fprintf(stderr, "%s: memdev active, abort perfcnt_mta_hif_cnt_val_latch\n",
      cxl_memdev_get_devname(memdev));
    return -EBUSY;
  }

  return cxl_memdev_perfcnt_mta_hif_cnt_val_latch(memdev, perfcnt_mta_hif_cnt_val_latch_params.counter);
}

static int action_cmd_perfcnt_ddr_generic_select(struct cxl_memdev *memdev, struct action_context *actx)
{
  if (cxl_memdev_is_active(memdev)) {
    fprintf(stderr, "%s: memdev active, abort perfcnt_ddr_generic_select\n",
      cxl_memdev_get_devname(memdev));
    return -EBUSY;
  }

  return cxl_memdev_perfcnt_ddr_generic_select(memdev, perfcnt_ddr_generic_select_params.ddr_id,
    perfcnt_ddr_generic_select_params.cid, perfcnt_ddr_generic_select_params.rank,
    perfcnt_ddr_generic_select_params.bank, perfcnt_ddr_generic_select_params.bankgroup,
    perfcnt_ddr_generic_select_params.event);
}

static int action_cmd_perfcnt_ddr_generic_capture(struct cxl_memdev *memdev, struct action_context *actx)
{
	if (cxl_memdev_is_active(memdev)) {
		fprintf(stderr, "%s: memdev active, abort perfcnt_ddr_generic_capture\n",
			cxl_memdev_get_devname(memdev));
		return -EBUSY;
	}

	return cxl_memdev_perfcnt_ddr_generic_capture(memdev, perfcnt_ddr_generic_capture_params.ddr_id,
		perfcnt_ddr_generic_capture_params.poll_period_ms
	);
}

static int action_cmd_perfcnt_ddr_dfi_capture(struct cxl_memdev *memdev, struct action_context *actx)
{
	if (cxl_memdev_is_active(memdev)) {
		fprintf(stderr, "%s: memdev active, abort perfcnt_ddr_dfi_capture\n",
			cxl_memdev_get_devname(memdev));
		return -EBUSY;
	}

	return cxl_memdev_perfcnt_ddr_dfi_capture(memdev, perfcnt_ddr_dfi_capture_params.ddr_id,
		perfcnt_ddr_dfi_capture_params.poll_period_ms
	);
}

static int action_cmd_err_inj_drs_poison(struct cxl_memdev *memdev, struct action_context *actx)
{
  if (cxl_memdev_is_active(memdev)) {
    fprintf(stderr, "%s: memdev active, abort err_inj_drs_poison\n",
      cxl_memdev_get_devname(memdev));
    return -EBUSY;
  }

  return cxl_memdev_err_inj_drs_poison(memdev, err_inj_drs_poison_params.ch_id,
    err_inj_drs_poison_params.duration, err_inj_drs_poison_params.inj_mode,
    err_inj_drs_poison_params.tag);
}

static int action_cmd_err_inj_drs_ecc(struct cxl_memdev *memdev, struct action_context *actx)
{
  if (cxl_memdev_is_active(memdev)) {
    fprintf(stderr, "%s: memdev active, abort err_inj_drs_ecc\n",
      cxl_memdev_get_devname(memdev));
    return -EBUSY;
  }

  return cxl_memdev_err_inj_drs_ecc(memdev, err_inj_drs_ecc_params.ch_id,
    err_inj_drs_ecc_params.duration, err_inj_drs_ecc_params.inj_mode,
    err_inj_drs_ecc_params.tag);
}

static int action_cmd_err_inj_rxflit_crc(struct cxl_memdev *memdev, struct action_context *actx)
{
  if (cxl_memdev_is_active(memdev)) {
    fprintf(stderr, "%s: memdev active, abort err_inj_rxflit_crc\n",
      cxl_memdev_get_devname(memdev));
    return -EBUSY;
  }

  return cxl_memdev_err_inj_rxflit_crc(memdev, err_inj_rxflit_crc_params.cxl_mem_id);
}

static int action_cmd_err_inj_txflit_crc(struct cxl_memdev *memdev, struct action_context *actx)
{
  if (cxl_memdev_is_active(memdev)) {
    fprintf(stderr, "%s: memdev active, abort err_inj_txflit_crc\n",
      cxl_memdev_get_devname(memdev));
    return -EBUSY;
  }

  return cxl_memdev_err_inj_txflit_crc(memdev, err_inj_txflit_crc_params.cxl_mem_id);
}

static int action_cmd_err_inj_viral(struct cxl_memdev *memdev, struct action_context *actx)
{
  if (cxl_memdev_is_active(memdev)) {
    fprintf(stderr, "%s: memdev active, abort err_inj_viral\n",
      cxl_memdev_get_devname(memdev));
    return -EBUSY;
  }

  return cxl_memdev_err_inj_viral(memdev, err_inj_viral_params.ld_id);
}

static int action_cmd_eh_eye_cap_run(struct cxl_memdev *memdev, struct action_context *actx)
{
  if (cxl_memdev_is_active(memdev)) {
    fprintf(stderr, "%s: memdev active, abort eh_eye_cap_run\n",
      cxl_memdev_get_devname(memdev));
    return -EBUSY;
  }

  return cxl_memdev_eh_eye_cap_run(memdev, eh_eye_cap_run_params.depth,
    eh_eye_cap_run_params.lane_mask);
}

static int action_cmd_eh_eye_cap_read(struct cxl_memdev *memdev, struct action_context *actx)
{
  if (cxl_memdev_is_active(memdev)) {
    fprintf(stderr, "%s: memdev active, abort eh_eye_cap_read\n",
      cxl_memdev_get_devname(memdev));
    return -EBUSY;
  }

  return cxl_memdev_eh_eye_cap_read(memdev, eh_eye_cap_read_params.lane_id,
    eh_eye_cap_read_params.bin_num);
}

static int action_cmd_eh_eye_cap_timeout_enable(struct cxl_memdev *memdev, struct action_context *actx)
{
  if (cxl_memdev_is_active(memdev)) {
    fprintf(stderr, "%s: memdev active, abort eh_eye_cap_timeout_enable\n",
      cxl_memdev_get_devname(memdev));
    return -EBUSY;
  }

  return cxl_memdev_eh_eye_cap_timeout_enable(memdev, eh_eye_cap_timeout_enable_params.enable);
}

static int action_cmd_eh_eye_cap_status(struct cxl_memdev *memdev, struct action_context *actx)
{
  if (cxl_memdev_is_active(memdev)) {
    fprintf(stderr, "%s: memdev active, abort eh_eye_cap_status\n",
      cxl_memdev_get_devname(memdev));
    return -EBUSY;
  }

  return cxl_memdev_eh_eye_cap_status(memdev);
}

static int action_cmd_eh_adapt_get(struct cxl_memdev *memdev, struct action_context *actx)
{
  if (cxl_memdev_is_active(memdev)) {
    fprintf(stderr, "%s: memdev active, abort eh_adapt_get\n",
      cxl_memdev_get_devname(memdev));
    return -EBUSY;
  }

  return cxl_memdev_eh_adapt_get(memdev, eh_adapt_get_params.lane_id);
}

static int action_cmd_eh_adapt_oneoff(struct cxl_memdev *memdev, struct action_context *actx)
{
  if (cxl_memdev_is_active(memdev)) {
    fprintf(stderr, "%s: memdev active, abort eh_adapt_oneoff\n",
      cxl_memdev_get_devname(memdev));
    return -EBUSY;
  }

  return cxl_memdev_eh_adapt_oneoff(memdev, eh_adapt_oneoff_params.lane_id,
    eh_adapt_oneoff_params.preload, eh_adapt_oneoff_params.loops, eh_adapt_oneoff_params.objects);
}

static int action_cmd_eh_adapt_force(struct cxl_memdev *memdev, struct action_context *actx)
{
  if (cxl_memdev_is_active(memdev)) {
    fprintf(stderr, "%s: memdev active, abort eh_adapt_force\n",
      cxl_memdev_get_devname(memdev));
    return -EBUSY;
  }

  return cxl_memdev_eh_adapt_force(memdev, eh_adapt_force_params.lane_id,
    eh_adapt_force_params.rate, eh_adapt_force_params.vdd_bias, eh_adapt_force_params.ssc,
    eh_adapt_force_params.pga_gain, eh_adapt_force_params.pga_a0, eh_adapt_force_params.pga_off,
    eh_adapt_force_params.cdfe_a2, eh_adapt_force_params.cdfe_a3, eh_adapt_force_params.cdfe_a4,
    eh_adapt_force_params.cdfe_a5, eh_adapt_force_params.cdfe_a6, eh_adapt_force_params.cdfe_a7,
    eh_adapt_force_params.cdfe_a8, eh_adapt_force_params.cdfe_a9, eh_adapt_force_params.cdfe_a10,
    eh_adapt_force_params.dc_offset, eh_adapt_force_params.zobel_dc_offset,
    eh_adapt_force_params.udfe_thr_0, eh_adapt_force_params.udfe_thr_1,
    eh_adapt_force_params.median_amp, eh_adapt_force_params.zobel_a_gain,
    eh_adapt_force_params.ph_ofs_t);
}

static int action_cmd_hbo_status(struct cxl_memdev *memdev, struct action_context *actx)
{
  if (cxl_memdev_is_active(memdev)) {
    fprintf(stderr, "%s: memdev active, abort hbo_status\n",
      cxl_memdev_get_devname(memdev));
    return -EBUSY;
  }

  return cxl_memdev_hbo_status(memdev, 1);
}

static int action_cmd_hbo_transfer_fw(struct cxl_memdev *memdev, struct action_context *actx)
{
  if (cxl_memdev_is_active(memdev)) {
    fprintf(stderr, "%s: memdev active, abort hbo_transfer_fw\n",
      cxl_memdev_get_devname(memdev));
    return -EBUSY;
  }

  return cxl_memdev_hbo_transfer_fw(memdev);
}

static int action_cmd_hbo_activate_fw(struct cxl_memdev *memdev, struct action_context *actx)
{
  if (cxl_memdev_is_active(memdev)) {
    fprintf(stderr, "%s: memdev active, abort hbo_activate_fw\n",
      cxl_memdev_get_devname(memdev));
    return -EBUSY;
  }

  return cxl_memdev_hbo_activate_fw(memdev);
}

static int action_cmd_health_counters_clear(struct cxl_memdev *memdev, struct action_context *actx)
{
  if (cxl_memdev_is_active(memdev)) {
    fprintf(stderr, "%s: memdev active, abort health_counters_clear\n",
      cxl_memdev_get_devname(memdev));
    return -EBUSY;
  }

  return cxl_memdev_health_counters_clear(memdev, health_counters_clear_params.bitmask);
}

static int action_cmd_health_counters_get(struct cxl_memdev *memdev, struct action_context *actx)
{
  if (cxl_memdev_is_active(memdev)) {
    fprintf(stderr, "%s: memdev active, abort health_counters_get\n",
      cxl_memdev_get_devname(memdev));
    return -EBUSY;
  }

  return cxl_memdev_health_counters_get(memdev);
}

static int action_cmd_hct_get_plat_param(struct cxl_memdev *memdev, struct action_context *actx)
{
  if (cxl_memdev_is_active(memdev)) {
    fprintf(stderr, "%s: memdev active, abort hct_get_plat_param\n",
      cxl_memdev_get_devname(memdev));
    return -EBUSY;
  }

  return cxl_memdev_hct_get_plat_param(memdev);
}

static int action_cmd_err_inj_hif_poison(struct cxl_memdev *memdev, struct action_context *actx)
{
	if (cxl_memdev_is_active(memdev)) {
		fprintf(stderr, "%s: memdev active, abort err_inj_hif_poison\n",
			cxl_memdev_get_devname(memdev));
		return -EBUSY;
	}

	return cxl_memdev_err_inj_hif_poison(memdev, err_inj_hif_poison_params.ch_id,
		err_inj_hif_poison_params.duration, err_inj_hif_poison_params.inj_mode,
		err_inj_hif_poison_params.address);
}

static int action_cmd_err_inj_hif_ecc(struct cxl_memdev *memdev, struct action_context *actx)
{
	if (cxl_memdev_is_active(memdev)) {
		fprintf(stderr, "%s: memdev active, abort err_inj_hif_ecc\n",
			cxl_memdev_get_devname(memdev));
		return -EBUSY;
	}

	return cxl_memdev_err_inj_hif_ecc(memdev, err_inj_hif_ecc_params.ch_id,
		err_inj_hif_ecc_params.duration, err_inj_hif_ecc_params.inj_mode,
		err_inj_hif_ecc_params.address);
}

static int action_cmd_eh_link_dbg_cfg(struct cxl_memdev *memdev, struct action_context *actx)
{
	if (cxl_memdev_is_active(memdev)) {
		fprintf(stderr, "%s: memdev active, abort eh_link_dbg_cfg\n",
			cxl_memdev_get_devname(memdev));
		return -EBUSY;
	}

	return cxl_memdev_eh_link_dbg_cfg(memdev, eh_link_dbg_cfg_params.port_id,
		eh_link_dbg_cfg_params.op_mode, eh_link_dbg_cfg_params.cap_type,
		eh_link_dbg_cfg_params.lane_mask, eh_link_dbg_cfg_params.rate_mask,
		eh_link_dbg_cfg_params.timer_us, eh_link_dbg_cfg_params.cap_delay_us,
		eh_link_dbg_cfg_params.max_cap);
}

static int action_cmd_eh_link_dbg_entry_dump(struct cxl_memdev *memdev, struct action_context *actx)
{
	if (cxl_memdev_is_active(memdev)) {
		fprintf(stderr, "%s: memdev active, abort eh_link_dbg_entry_dump\n",
			cxl_memdev_get_devname(memdev));
		return -EBUSY;
	}

	return cxl_memdev_eh_link_dbg_entry_dump(memdev, eh_link_dbg_entry_dump_params.entry_idx);
}

static int action_cmd_eh_link_dbg_lane_dump(struct cxl_memdev *memdev, struct action_context *actx)
{
	if (cxl_memdev_is_active(memdev)) {
		fprintf(stderr, "%s: memdev active, abort eh_link_dbg_lane_dump\n",
			cxl_memdev_get_devname(memdev));
		return -EBUSY;
	}

	return cxl_memdev_eh_link_dbg_lane_dump(memdev, eh_link_dbg_lane_dump_params.entry_idx,
		eh_link_dbg_lane_dump_params.lane_idx);
}

static int action_cmd_eh_link_dbg_reset(struct cxl_memdev *memdev, struct action_context *actx)
{
	if (cxl_memdev_is_active(memdev)) {
		fprintf(stderr, "%s: memdev active, abort eh_link_dbg_reset\n",
			cxl_memdev_get_devname(memdev));
		return -EBUSY;
	}

	return cxl_memdev_eh_link_dbg_reset(memdev);
}

static int action_cmd_fbist_stopconfig_set(struct cxl_memdev *memdev, struct action_context *actx)
{
	if (cxl_memdev_is_active(memdev)) {
		fprintf(stderr, "%s: memdev active, abort fbist_stopconfig_set\n",
			cxl_memdev_get_devname(memdev));
		return -EBUSY;
	}

	return cxl_memdev_fbist_stopconfig_set(memdev, fbist_stopconfig_set_params.fbist_id,
		fbist_stopconfig_set_params.stop_on_wresp, fbist_stopconfig_set_params.stop_on_rresp,
		fbist_stopconfig_set_params.stop_on_rdataerr);
}

static int action_cmd_fbist_cyclecount_set(struct cxl_memdev *memdev, struct action_context *actx)
{
	if (cxl_memdev_is_active(memdev)) {
		fprintf(stderr, "%s: memdev active, abort fbist_cyclecount_set\n",
			cxl_memdev_get_devname(memdev));
		return -EBUSY;
	}

	return cxl_memdev_fbist_cyclecount_set(memdev, fbist_cyclecount_set_params.fbist_id,
		fbist_cyclecount_set_params.txg_nr, fbist_cyclecount_set_params.cyclecount);
}

static int action_cmd_fbist_reset_set(struct cxl_memdev *memdev, struct action_context *actx)
{
	if (cxl_memdev_is_active(memdev)) {
		fprintf(stderr, "%s: memdev active, abort fbist_reset_set\n",
			cxl_memdev_get_devname(memdev));
		return -EBUSY;
	}

	return cxl_memdev_fbist_reset_set(memdev, fbist_reset_set_params.fbist_id,
		fbist_reset_set_params.txg0_reset, fbist_reset_set_params.txg1_reset);
}

static int action_cmd_fbist_run_set(struct cxl_memdev *memdev, struct action_context *actx)
{
	if (cxl_memdev_is_active(memdev)) {
		fprintf(stderr, "%s: memdev active, abort fbist_run_set\n",
			cxl_memdev_get_devname(memdev));
		return -EBUSY;
	}

	return cxl_memdev_fbist_run_set(memdev, fbist_run_set_params.fbist_id,
		fbist_run_set_params.txg0_run, fbist_run_set_params.txg1_run);
}

static int action_cmd_fbist_run_get(struct cxl_memdev *memdev, struct action_context *actx)
{
	if (cxl_memdev_is_active(memdev)) {
		fprintf(stderr, "%s: memdev active, abort fbist_run_get\n",
			cxl_memdev_get_devname(memdev));
		return -EBUSY;
	}

	return cxl_memdev_fbist_run_get(memdev, fbist_run_get_params.fbist_id);
}

static int action_cmd_fbist_xfer_rem_cnt_get(struct cxl_memdev *memdev, struct action_context *actx)
{
	if (cxl_memdev_is_active(memdev)) {
		fprintf(stderr, "%s: memdev active, abort fbist_xfer_rem_cnt_get\n",
			cxl_memdev_get_devname(memdev));
		return -EBUSY;
	}

	return cxl_memdev_fbist_xfer_rem_cnt_get(memdev, fbist_xfer_rem_cnt_get_params.fbist_id,
		fbist_xfer_rem_cnt_get_params.thread_nr);
}

static int action_cmd_fbist_last_exp_read_data_get(struct cxl_memdev *memdev, struct action_context *actx)
{
	if (cxl_memdev_is_active(memdev)) {
		fprintf(stderr, "%s: memdev active, abort fbist_last_exp_read_data_get\n",
			cxl_memdev_get_devname(memdev));
		return -EBUSY;
	}

	return cxl_memdev_fbist_last_exp_read_data_get(memdev, fbist_last_exp_read_data_get_params.fbist_id);
}

static int action_cmd_fbist_curr_cycle_cnt_get(struct cxl_memdev *memdev, struct action_context *actx)
{
	if (cxl_memdev_is_active(memdev)) {
		fprintf(stderr, "%s: memdev active, abort fbist_curr_cycle_cnt_get\n",
			cxl_memdev_get_devname(memdev));
		return -EBUSY;
	}

	return cxl_memdev_fbist_curr_cycle_cnt_get(memdev, fbist_curr_cycle_cnt_get_params.fbist_id,
		fbist_curr_cycle_cnt_get_params.txg_nr);
}

static int action_cmd_fbist_thread_status_get(struct cxl_memdev *memdev, struct action_context *actx)
{
	if (cxl_memdev_is_active(memdev)) {
		fprintf(stderr, "%s: memdev active, abort fbist_thread_status_get\n",
			cxl_memdev_get_devname(memdev));
		return -EBUSY;
	}

	return cxl_memdev_fbist_thread_status_get(memdev, fbist_thread_status_get_params.fbist_id,
		fbist_thread_status_get_params.txg_nr, fbist_thread_status_get_params.thread_nr);
}

static int action_cmd_fbist_thread_trans_cnt_get(struct cxl_memdev *memdev, struct action_context *actx)
{
	if (cxl_memdev_is_active(memdev)) {
		fprintf(stderr, "%s: memdev active, abort fbist_thread_trans_cnt_get\n",
			cxl_memdev_get_devname(memdev));
		return -EBUSY;
	}

	return cxl_memdev_fbist_thread_trans_cnt_get(memdev, fbist_thread_trans_cnt_get_params.fbist_id,
		fbist_thread_trans_cnt_get_params.txg_nr, fbist_thread_trans_cnt_get_params.thread_nr);
}

static int action_cmd_fbist_thread_bandwidth_get(struct cxl_memdev *memdev, struct action_context *actx)
{
	if (cxl_memdev_is_active(memdev)) {
		fprintf(stderr, "%s: memdev active, abort fbist_thread_bandwidth_get\n",
			cxl_memdev_get_devname(memdev));
		return -EBUSY;
	}

	return cxl_memdev_fbist_thread_bandwidth_get(memdev, fbist_thread_bandwidth_get_params.fbist_id,
		fbist_thread_bandwidth_get_params.txg_nr, fbist_thread_bandwidth_get_params.thread_nr);
}

static int action_cmd_fbist_thread_latency_get(struct cxl_memdev *memdev, struct action_context *actx)
{
	if (cxl_memdev_is_active(memdev)) {
		fprintf(stderr, "%s: memdev active, abort fbist_thread_latency_get\n",
			cxl_memdev_get_devname(memdev));
		return -EBUSY;
	}

	return cxl_memdev_fbist_thread_latency_get(memdev, fbist_thread_latency_get_params.fbist_id,
		fbist_thread_latency_get_params.txg_nr, fbist_thread_latency_get_params.thread_nr);
}

static int action_cmd_fbist_thread_perf_mon_set(struct cxl_memdev *memdev, struct action_context *actx)
{
	if (cxl_memdev_is_active(memdev)) {
		fprintf(stderr, "%s: memdev active, abort fbist_thread_perf_mon_set\n",
			cxl_memdev_get_devname(memdev));
		return -EBUSY;
	}

	return cxl_memdev_fbist_thread_perf_mon_set(memdev, fbist_thread_perf_mon_set_params.fbist_id,
		fbist_thread_perf_mon_set_params.txg_nr, fbist_thread_perf_mon_set_params.thread_nr,
		fbist_thread_perf_mon_set_params.pmon_preset_en, fbist_thread_perf_mon_set_params.pmon_clear_en,
		fbist_thread_perf_mon_set_params.pmon_rollover, fbist_thread_perf_mon_set_params.pmon_thread_lclk);
}

static int action_cmd_fbist_top_read_status0_get(struct cxl_memdev *memdev, struct action_context *actx)
{
	if (cxl_memdev_is_active(memdev)) {
		fprintf(stderr, "%s: memdev active, abort fbist_top_read_status0_get\n",
			cxl_memdev_get_devname(memdev));
		return -EBUSY;
	}

	return cxl_memdev_fbist_top_read_status0_get(memdev, fbist_top_read_status0_get_params.fbist_id);
}

static int action_cmd_fbist_top_err_cnt_get(struct cxl_memdev *memdev, struct action_context *actx)
{
	if (cxl_memdev_is_active(memdev)) {
		fprintf(stderr, "%s: memdev active, abort fbist_top_err_cnt_get\n",
			cxl_memdev_get_devname(memdev));
		return -EBUSY;
	}

	return cxl_memdev_fbist_top_err_cnt_get(memdev, fbist_top_err_cnt_get_params.fbist_id);
}

static int action_cmd_fbist_last_read_addr_get(struct cxl_memdev *memdev, struct action_context *actx)
{
	if (cxl_memdev_is_active(memdev)) {
		fprintf(stderr, "%s: memdev active, abort fbist_last_read_addr_get\n",
			cxl_memdev_get_devname(memdev));
		return -EBUSY;
	}

	return cxl_memdev_fbist_last_read_addr_get(memdev, fbist_last_read_addr_get_params.fbist_id);
}

static int action_cmd_fbist_test_simpledata(struct cxl_memdev *memdev, struct action_context *actx)
{
	if (cxl_memdev_is_active(memdev)) {
		fprintf(stderr, "%s: memdev active, abort fbist_test_simpledata\n",
			cxl_memdev_get_devname(memdev));
		return -EBUSY;
	}

	return cxl_memdev_fbist_test_simpledata(memdev, fbist_test_simpledata_params.fbist_id,
		fbist_test_simpledata_params.test_nr, fbist_test_simpledata_params.start_address,
		fbist_test_simpledata_params.num_bytes);
}

static int action_cmd_fbist_test_addresstest(struct cxl_memdev *memdev, struct action_context *actx)
{
	if (cxl_memdev_is_active(memdev)) {
		fprintf(stderr, "%s: memdev active, abort fbist_test_addresstest\n",
			cxl_memdev_get_devname(memdev));
		return -EBUSY;
	}

	return cxl_memdev_fbist_test_addresstest(memdev, fbist_test_addresstest_params.fbist_id,
		fbist_test_addresstest_params.test_nr, fbist_test_addresstest_params.start_address,
		fbist_test_addresstest_params.num_bytes, fbist_test_addresstest_params.seed);
}

static int action_cmd_fbist_test_movinginversion(struct cxl_memdev *memdev, struct action_context *actx)
{
	if (cxl_memdev_is_active(memdev)) {
		fprintf(stderr, "%s: memdev active, abort fbist_test_movinginversion\n",
			cxl_memdev_get_devname(memdev));
		return -EBUSY;
	}

	return cxl_memdev_fbist_test_movinginversion(memdev, fbist_test_movinginversion_params.fbist_id,
		fbist_test_movinginversion_params.test_nr, fbist_test_movinginversion_params.phase_nr,
		fbist_test_movinginversion_params.start_address, fbist_test_movinginversion_params.num_bytes,
		fbist_test_movinginversion_params.ddrpage_size);
}

static int action_cmd_fbist_test_randomsequence(struct cxl_memdev *memdev, struct action_context *actx)
{
	if (cxl_memdev_is_active(memdev)) {
		fprintf(stderr, "%s: memdev active, abort fbist_test_randomsequence\n",
			cxl_memdev_get_devname(memdev));
		return -EBUSY;
	}

	return cxl_memdev_fbist_test_randomsequence(memdev, fbist_test_randomsequence_params.fbist_id,
		fbist_test_randomsequence_params.phase_nr, fbist_test_randomsequence_params.start_address,
		fbist_test_randomsequence_params.num_bytes, fbist_test_randomsequence_params.ddrpage_size,
		fbist_test_randomsequence_params.seed_dr0, fbist_test_randomsequence_params.seed_dr1);
}


static int action_cmd_conf_read(struct cxl_memdev *memdev, struct action_context *actx)
{
	if (cxl_memdev_is_active(memdev)) {
		fprintf(stderr, "%s: memdev active, abort conf_read\n",
			cxl_memdev_get_devname(memdev));
		return -EBUSY;
	}

	return cxl_memdev_conf_read(memdev, conf_read_params.offset, conf_read_params.length);
}

static int action_zero(struct cxl_memdev *memdev, struct action_context *actx)
{
  int rc;

  if (cxl_memdev_is_active(memdev)) {
    fprintf(stderr, "%s: memdev active, abort label write\n",
      cxl_memdev_get_devname(memdev));
    return -EBUSY;
  }

  rc = cxl_memdev_zero_lsa(memdev);
  if (rc < 0)
    fprintf(stderr, "%s: label zeroing failed: %s\n",
      cxl_memdev_get_devname(memdev), strerror(-rc));

  return rc;
}

static int action_cmd_hct_get_config(struct cxl_memdev *memdev, struct action_context *actx)
{
	if (cxl_memdev_is_active(memdev)) {
		fprintf(stderr, "%s: memdev active, abort hct_get_config\n",
			cxl_memdev_get_devname(memdev));
		return -EBUSY;
	}

	return cxl_memdev_hct_get_config(memdev, hct_get_config_params.hct_inst);
}

static int action_cmd_hct_read_buffer(struct cxl_memdev *memdev, struct action_context *actx)
{
	if (cxl_memdev_is_active(memdev)) {
		fprintf(stderr, "%s: memdev active, abort hct_read_buffer\n",
			cxl_memdev_get_devname(memdev));
		return -EBUSY;
	}

	return cxl_memdev_hct_read_buffer(memdev, hct_read_buffer_params.hct_inst,
		hct_read_buffer_params.num_entries_to_read);
}

static int action_cmd_hct_set_config(struct cxl_memdev *memdev, struct action_context *actx)
{
  struct stat filestat;
  int filesize;
  FILE *trig_config;
  int fd;
  int rc;
  u8 *trig_config_buffer;
  int conf_read;

  trig_config = fopen(hct_set_config_params.trig_config_file, "rb");
  if (trig_config == NULL) {
    fprintf(stderr, "Error: File open returned %s\nCould not open file %s\n",
                  strerror(errno), hct_set_config_params.trig_config_file);
    return -ENOENT;
  }

  printf("Trigger Config filepath: %s\n", hct_set_config_params.trig_config_file);
  fd = fileno(trig_config);
  rc = fstat(fd, &filestat);

  if (rc != 0) {
    fprintf(stderr, "Could not read filesize");
    fclose(trig_config);
    return 1;
  }

	if (cxl_memdev_is_active(memdev)) {
		fprintf(stderr, "%s: memdev active, abort hct_set_config\n",
			cxl_memdev_get_devname(memdev));
		return -EBUSY;
	}

  filesize = filestat.st_size;

  trig_config_buffer = (u8*) malloc(filesize);
  conf_read = fread(trig_config_buffer, 1, filesize, trig_config);
  if (conf_read != filesize){
    fprintf(stderr, "Expected size: %d\nRead size: %d\n", filesize, conf_read);
    free(trig_config_buffer);
    fclose(trig_config);
    return -ENOENT;
  }
  printf("Expected size: %d\nRead size: %d\n", filesize, conf_read);

	return cxl_memdev_hct_set_config(memdev, hct_set_config_params.hct_inst,
    hct_set_config_params.config_flags, hct_set_config_params.post_trig_depth,
    hct_set_config_params.ignore_valid, filesize, trig_config_buffer);
}


static int action_write(struct cxl_memdev *memdev, struct action_context *actx)
{
  size_t size = param.len, read_len;
  unsigned char *buf;
  int rc;

  if (cxl_memdev_is_active(memdev)) {
    fprintf(stderr, "%s is active, abort label write\n",
      cxl_memdev_get_devname(memdev));
    return -EBUSY;
  }

  if (!size) {
    size_t lsa_size = cxl_memdev_get_lsa_size(memdev);

    fseek(actx->f_in, 0L, SEEK_END);
    size = ftell(actx->f_in);
    fseek(actx->f_in, 0L, SEEK_SET);

    if (size > lsa_size) {
      fprintf(stderr,
        "File size (%zu) greater than LSA size (%zu), aborting\n",
        size, lsa_size);
      return -EINVAL;
    }
  }

  buf = calloc(1, size);
  if (!buf)
    return -ENOMEM;

  read_len = fread(buf, 1, size, actx->f_in);
  if (read_len != size) {
    rc = -ENXIO;
    goto out;
  }

  rc = cxl_memdev_set_lsa(memdev, buf, size, param.offset);
  if (rc < 0)
    fprintf(stderr, "%s: label write failed: %s\n",
      cxl_memdev_get_devname(memdev), strerror(-rc));

out:
  free(buf);
  return rc;
}

static int action_read(struct cxl_memdev *memdev, struct action_context *actx)
{
  size_t size = param.len, write_len;
  char *buf;
  int rc;

  if (!size)
    size = cxl_memdev_get_lsa_size(memdev);

  buf = calloc(1, size);
  if (!buf)
    return -ENOMEM;

  rc = cxl_memdev_get_lsa(memdev, buf, size, param.offset);
  if (rc < 0) {
    fprintf(stderr, "%s: label read failed: %s\n",
      cxl_memdev_get_devname(memdev), strerror(-rc));
    goto out;
  }

  write_len = fwrite(buf, 1, size, actx->f_out);
  if (write_len != size) {
    rc = -ENXIO;
    goto out;
  }
  fflush(actx->f_out);

out:
  free(buf);
  return rc;
}

static int memdev_action(int argc, const char **argv, struct cxl_ctx *ctx,
    int (*action)(struct cxl_memdev *memdev, struct action_context *actx),
    const struct option *options, const char *usage)
{
  struct cxl_memdev *memdev, *single = NULL;
  struct action_context actx = { 0 };
  int i, rc = 0, count = 0, err = 0;
  const char * const u[] = {
    usage,
    NULL
  };
  unsigned long id;

  argc = parse_options(argc, argv, options, u, 0);

  if (argc == 0)
    usage_with_options(u, options);
  for (i = 0; i < argc; i++) {
    if (strcmp(argv[i], "all") == 0) {
      argv[0] = "all";
      argc = 1;
      break;
    }

    if (sscanf(argv[i], "mem%lu", &id) != 1) {
      fprintf(stderr, "'%s' is not a valid memdev name\n",
          argv[i]);
      err++;
    }
  }

  if (err == argc) {
    usage_with_options(u, options);
    return -EINVAL;
  }

  if (!param.outfile)
    actx.f_out = stdout;
  else {
    actx.f_out = fopen(param.outfile, "w+");
    if (!actx.f_out) {
      fprintf(stderr, "failed to open: %s: (%s)\n",
          param.outfile, strerror(errno));
      rc = -errno;
      goto out;
    }
  }

  if (!param.infile) {
    actx.f_in = stdin;
  } else {
    actx.f_in = fopen(param.infile, "r");
    if (!actx.f_in) {
      fprintf(stderr, "failed to open: %s: (%s)\n",
          param.infile, strerror(errno));
      rc = -errno;
      goto out_close_fout;
    }
  }

  if (param.verbose){
    cxl_set_log_priority(ctx, LOG_DEBUG);
  }
  rc = 0;
  err = 0;
  count = 0;

  for (i = 0; i < argc; i++) {
    if (sscanf(argv[i], "mem%lu", &id) != 1
        && strcmp(argv[i], "all") != 0)
      continue;

    cxl_memdev_foreach (ctx, memdev) {
      if (!util_cxl_memdev_filter(memdev, argv[i]))
        continue;

      if (action == action_write) {
        single = memdev;
        rc = 0;
      } else
        rc = action(memdev, &actx);

      if (rc == 0)
        count++;
      else if (rc && !err)
        err = rc;
    }
  }
  rc = err;

  if (action == action_write) {
    if (count > 1) {
      error("write-labels only supports writing a single memdev\n");
      usage_with_options(u, options);
      return -EINVAL;
    } else if (single) {
      rc = action(single, &actx);
      if (rc)
        count = 0;
    }
  }

  if (actx.f_in != stdin)
    fclose(actx.f_in);

 out_close_fout:
  if (actx.f_out != stdout)
    fclose(actx.f_out);

 out:
  /*
   * count if some actions succeeded, 0 if none were attempted,
   * negative error code otherwise.
   */
  if (count > 0)
    return count;
  return rc;
}

int cmd_write_labels(int argc, const char **argv, struct cxl_ctx *ctx)
{
  int count = memdev_action(argc, argv, ctx, action_write, write_options,
      "cxl write-labels <memdev> [-i <filename>]");

  fprintf(stderr, "wrote %d mem%s\n", count >= 0 ? count : 0,
      count > 1 ? "s" : "");
  return count >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_read_labels(int argc, const char **argv, struct cxl_ctx *ctx)
{
  int count = memdev_action(argc, argv, ctx, action_read, read_options,
      "cxl read-labels <mem0> [<mem1>..<memN>] [-o <filename>]");

  fprintf(stderr, "read %d mem%s\n", count >= 0 ? count : 0,
      count > 1 ? "s" : "");
  return count >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_zero_labels(int argc, const char **argv, struct cxl_ctx *ctx)
{
  int count = memdev_action(argc, argv, ctx, action_zero, zero_options,
      "cxl zero-labels <mem0> [<mem1>..<memN>] [<options>]");

  fprintf(stderr, "zeroed %d mem%s\n", count >= 0 ? count : 0,
      count > 1 ? "s" : "");
  return count >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_identify(int argc, const char **argv, struct cxl_ctx *ctx)
{
  int rc = memdev_action(argc, argv, ctx, action_cmd_identify, cmd_identify_options,
      "cxl id-cmd <mem0> [<mem1>..<memN>] [<options>]");

  return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_get_supported_logs(int argc, const char **argv, struct cxl_ctx *ctx)
{
  int rc = memdev_action(argc, argv, ctx, action_cmd_get_supported_logs, cmd_get_supported_logs_options,
      "cxl get-supported-logs <mem0> [<mem1>..<memN>] [<options>]");

  return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_get_cel_log(int argc, const char **argv, struct cxl_ctx *ctx)
{
  int rc = memdev_action(argc, argv, ctx, action_cmd_get_cel_log, cmd_get_cel_log_options,
      "cxl get-cel-log <mem0> [<mem1>..<memN>] [<options>]");

  return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_get_event_interrupt_policy(int argc, const char **argv, struct cxl_ctx *ctx)
{
  int rc = memdev_action(argc, argv, ctx, action_cmd_get_event_interrupt_policy, cmd_get_event_interrupt_policy_options,
      "cxl get-event-interrupt-policy <mem0> [<mem1>..<memN>] [<options>]");

  return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_set_event_interrupt_policy(int argc, const char **argv, struct cxl_ctx *ctx)
{
  int rc = memdev_action(argc, argv, ctx, action_cmd_set_event_interrupt_policy, cmd_set_event_interrupt_policy_options,
      "cxl set-event-interrupt-policy <mem0> [<mem1>..<memN>] [<options>]");

  return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_get_timestamp(int argc, const char **argv, struct cxl_ctx *ctx)
{
  int rc = memdev_action(argc, argv, ctx, action_cmd_get_timestamp, cmd_get_timestamp_options,
      "cxl get-timestamp <mem0> [<mem1>..<memN>] [<options>]");

  return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_device_info_get(int argc, const char **argv, struct cxl_ctx *ctx)
{
  int rc = memdev_action(argc, argv, ctx, action_cmd_device_info_get, cmd_device_info_get_options,
      "cxl device_info_get <mem0> [<mem1>..<memN>] [<options>]");

  return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_get_fw_info(int argc, const char **argv, struct cxl_ctx *ctx)
{
  int rc = memdev_action(argc, argv, ctx, action_cmd_get_fw_info, cmd_get_fw_info_options,
      "cxl get_fw_info <mem0> [<mem1>..<memN>] [<options>]");

  return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_activate_fw(int argc, const char **argv, struct cxl_ctx *ctx)
{
  int rc = memdev_action(argc, argv, ctx, action_cmd_activate_fw, cmd_activate_fw_options,
      "cxl activate_fw <mem0> [<mem1>..<memN>] [<options>]");

  return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_set_timestamp(int argc, const char **argv, struct cxl_ctx *ctx)
{
  int rc = memdev_action(argc, argv, ctx, action_cmd_set_timestamp, cmd_set_timestamp_options,
      "cxl set-timestamp <mem0> [<mem1>..<memN>] [<options>]");

  return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_get_alert_config(int argc, const char **argv, struct cxl_ctx *ctx)
{
  int rc = memdev_action(argc, argv, ctx, action_cmd_get_alert_config, cmd_get_alert_config_options,
      "cxl get-alert-config <mem0> [<mem1>..<memN>] [<options>]");

  return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_update_fw(int argc, const char **argv, struct cxl_ctx *ctx)
{
  int rc = memdev_action(argc, argv, ctx, action_cmd_update_fw, cmd_update_fw_options,
      "cxl update-fw <mem0> [<mem1>..<memN>] [<options>]");

  return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_set_alert_config(int argc, const char **argv, struct cxl_ctx *ctx)
{
  int rc = memdev_action(argc, argv, ctx, action_cmd_set_alert_config, cmd_set_alert_config_options,
      "cxl set-alert-config <mem0> [<mem1>..<memN>] [<options>]");

  return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_get_health_info(int argc, const char **argv, struct cxl_ctx *ctx)
{
  int rc = memdev_action(argc, argv, ctx, action_cmd_get_health_info, cmd_get_health_info_options,
      "cxl get-health-info <mem0> [<mem1>..<memN>] [<options>]");

  return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_get_event_records(int argc, const char **argv, struct cxl_ctx *ctx)
{
  int rc = memdev_action(argc, argv, ctx, action_cmd_get_event_records, cmd_get_event_records_options,
      "cxl get-event-records <mem0> [<mem1>..<memN>] [<options>]");

  return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_get_ld_info(int argc, const char **argv, struct cxl_ctx *ctx)
{
  int rc = memdev_action(argc, argv, ctx, action_cmd_get_ld_info, cmd_get_ld_info_options,
      "cxl get-ld-info <mem0> [<mem1>..<memN>] [<options>]");

  return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_ddr_info(int argc, const char **argv, struct cxl_ctx *ctx)
{
  int rc = memdev_action(argc, argv, ctx, action_cmd_ddr_info, cmd_ddr_info_options,
      "cxl ddr-info <mem0> [<mem1>..<memN>] [-i <ddr_instance_id>]");

  return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_clear_event_records(int argc, const char **argv, struct cxl_ctx *ctx)
{
  int rc = memdev_action(argc, argv, ctx, action_cmd_clear_event_records, cmd_clear_event_records_options,
      "cxl clear-event-records <mem0> [<mem1>..<memN>] [<options>]");

  return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_hct_start_stop_trigger(int argc, const char **argv, struct cxl_ctx *ctx)
{
  int rc = memdev_action(argc, argv, ctx, action_cmd_hct_start_stop_trigger, cmd_hct_start_stop_trigger_options,
      "cxl hct_start_stop_trigger <mem0> [<mem1>..<memN>] [<options>]");

  return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_hct_get_buffer_status(int argc, const char **argv, struct cxl_ctx *ctx)
{
  int rc = memdev_action(argc, argv, ctx, action_cmd_hct_get_buffer_status, cmd_hct_get_buffer_status_options,
      "cxl hct_get_buffer_status <mem0> [<mem1>..<memN>] [<options>]");

  return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_hct_enable(int argc, const char **argv, struct cxl_ctx *ctx)
{
  int rc = memdev_action(argc, argv, ctx, action_cmd_hct_enable, cmd_hct_enable_options,
      "cxl hct_enable <mem0> [<mem1>..<memN>] [<options>]");

  return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_ltmon_capture_clear(int argc, const char **argv, struct cxl_ctx *ctx)
{
  int rc = memdev_action(argc, argv, ctx, action_cmd_ltmon_capture_clear, cmd_ltmon_capture_clear_options,
      "cxl ltmon_capture_clear <mem0> [<mem1>..<memN>] [<options>]");

  return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_ltmon_capture(int argc, const char **argv, struct cxl_ctx *ctx)
{
  int rc = memdev_action(argc, argv, ctx, action_cmd_ltmon_capture, cmd_ltmon_capture_options,
      "cxl ltmon_capture <mem0> [<mem1>..<memN>] [<options>]");

  return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_ltmon_capture_freeze_and_restore(int argc, const char **argv, struct cxl_ctx *ctx)
{
  int rc = memdev_action(argc, argv, ctx, action_cmd_ltmon_capture_freeze_and_restore, cmd_ltmon_capture_freeze_and_restore_options,
      "cxl ltmon_capture_freeze_and_restore <mem0> [<mem1>..<memN>] [<options>]");

  return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_ltmon_l2r_count_dump(int argc, const char **argv, struct cxl_ctx *ctx)
{
  int rc = memdev_action(argc, argv, ctx, action_cmd_ltmon_l2r_count_dump, cmd_ltmon_l2r_count_dump_options,
      "cxl ltmon_l2r_count_dump <mem0> [<mem1>..<memN>] [<options>]");

  return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_ltmon_l2r_count_clear(int argc, const char **argv, struct cxl_ctx *ctx)
{
  int rc = memdev_action(argc, argv, ctx, action_cmd_ltmon_l2r_count_clear, cmd_ltmon_l2r_count_clear_options,
      "cxl ltmon_l2r_count_clear <mem0> [<mem1>..<memN>] [<options>]");

  return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_ltmon_basic_cfg(int argc, const char **argv, struct cxl_ctx *ctx)
{
  int rc = memdev_action(argc, argv, ctx, action_cmd_ltmon_basic_cfg, cmd_ltmon_basic_cfg_options,
      "cxl ltmon_basic_cfg <mem0> [<mem1>..<memN>] [<options>]");

  return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_ltmon_watch(int argc, const char **argv, struct cxl_ctx *ctx)
{
  int rc = memdev_action(argc, argv, ctx, action_cmd_ltmon_watch, cmd_ltmon_watch_options,
      "cxl ltmon_watch <mem0> [<mem1>..<memN>] [<options>]");

  return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_ltmon_capture_stat(int argc, const char **argv, struct cxl_ctx *ctx)
{
  int rc = memdev_action(argc, argv, ctx, action_cmd_ltmon_capture_stat, cmd_ltmon_capture_stat_options,
      "cxl ltmon_capture_stat <mem0> [<mem1>..<memN>] [<options>]");

  return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_ltmon_capture_log_dmp(int argc, const char **argv, struct cxl_ctx *ctx)
{
  int rc = memdev_action(argc, argv, ctx, action_cmd_ltmon_capture_log_dmp, cmd_ltmon_capture_log_dmp_options,
      "cxl ltmon_capture_log_dmp <mem0> [<mem1>..<memN>] [<options>]");

  return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_ltmon_capture_trigger(int argc, const char **argv, struct cxl_ctx *ctx)
{
  int rc = memdev_action(argc, argv, ctx, action_cmd_ltmon_capture_trigger, cmd_ltmon_capture_trigger_options,
      "cxl ltmon_capture_trigger <mem0> [<mem1>..<memN>] [<options>]");

  return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_ltmon_enable(int argc, const char **argv, struct cxl_ctx *ctx)
{
  int rc = memdev_action(argc, argv, ctx, action_cmd_ltmon_enable, cmd_ltmon_enable_options,
      "cxl ltmon_enable <mem0> [<mem1>..<memN>] [<options>]");

  return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_osa_os_type_trig_cfg(int argc, const char **argv, struct cxl_ctx *ctx)
{
  int rc = memdev_action(argc, argv, ctx, action_cmd_osa_os_type_trig_cfg, cmd_osa_os_type_trig_cfg_options,
      "cxl osa_os_type_trig_cfg <mem0> [<mem1>..<memN>] [<options>]");

  return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_osa_cap_ctrl(int argc, const char **argv, struct cxl_ctx *ctx)
{
  int rc = memdev_action(argc, argv, ctx, action_cmd_osa_cap_ctrl, cmd_osa_cap_ctrl_options,
      "cxl osa_cap_ctrl <mem0> [<mem1>..<memN>] [<options>]");

  return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_osa_cfg_dump(int argc, const char **argv, struct cxl_ctx *ctx)
{
  int rc = memdev_action(argc, argv, ctx, action_cmd_osa_cfg_dump, cmd_osa_cfg_dump_options,
      "cxl osa_cfg_dump <mem0> [<mem1>..<memN>] [<options>]");

  return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_osa_ana_op(int argc, const char **argv, struct cxl_ctx *ctx)
{
  int rc = memdev_action(argc, argv, ctx, action_cmd_osa_ana_op, cmd_osa_ana_op_options,
      "cxl osa_ana_op <mem0> [<mem1>..<memN>] [<options>]");

  return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_osa_status_query(int argc, const char **argv, struct cxl_ctx *ctx)
{
  int rc = memdev_action(argc, argv, ctx, action_cmd_osa_status_query, cmd_osa_status_query_options,
      "cxl osa_status_query <mem0> [<mem1>..<memN>] [<options>]");

  return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_osa_access_rel(int argc, const char **argv, struct cxl_ctx *ctx)
{
  int rc = memdev_action(argc, argv, ctx, action_cmd_osa_access_rel, cmd_osa_access_rel_options,
      "cxl osa_access_rel <mem0> [<mem1>..<memN>] [<options>]");

  return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_perfcnt_mta_ltif_set(int argc, const char **argv, struct cxl_ctx *ctx)
{
  int rc = memdev_action(argc, argv, ctx, action_cmd_perfcnt_mta_ltif_set, cmd_perfcnt_mta_ltif_set_options,
      "cxl perfcnt_mta_ltif_set <mem0> [<mem1>..<memN>] [<options>]");

  return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_perfcnt_mta_get(int argc, const char **argv, struct cxl_ctx *ctx)
{
  int rc = memdev_action(argc, argv, ctx, action_cmd_perfcnt_mta_get, cmd_perfcnt_mta_get_options,
      "cxl perfcnt_mta_get <mem0> [<mem1>..<memN>] [<options>]");

  return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_perfcnt_mta_latch_val_get(int argc, const char **argv, struct cxl_ctx *ctx)
{
  int rc = memdev_action(argc, argv, ctx, action_cmd_perfcnt_mta_latch_val_get, cmd_perfcnt_mta_latch_val_get_options,
      "cxl perfcnt_mta_latch_val_get <mem0> [<mem1>..<memN>] [<options>]");

  return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_perfcnt_mta_counter_clear(int argc, const char **argv, struct cxl_ctx *ctx)
{
  int rc = memdev_action(argc, argv, ctx, action_cmd_perfcnt_mta_counter_clear, cmd_perfcnt_mta_counter_clear_options,
      "cxl perfcnt_mta_counter_clear <mem0> [<mem1>..<memN>] [<options>]");

  return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_perfcnt_mta_cnt_val_latch(int argc, const char **argv, struct cxl_ctx *ctx)
{
  int rc = memdev_action(argc, argv, ctx, action_cmd_perfcnt_mta_cnt_val_latch, cmd_perfcnt_mta_cnt_val_latch_options,
      "cxl perfcnt_mta_cnt_val_latch <mem0> [<mem1>..<memN>] [<options>]");

  return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_perfcnt_mta_hif_set(int argc, const char **argv, struct cxl_ctx *ctx)
{
  int rc = memdev_action(argc, argv, ctx, action_cmd_perfcnt_mta_hif_set, cmd_perfcnt_mta_hif_set_options,
      "cxl perfcnt_mta_hif_set <mem0> [<mem1>..<memN>] [<options>]");

  return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_perfcnt_mta_hif_cfg_get(int argc, const char **argv, struct cxl_ctx *ctx)
{
  int rc = memdev_action(argc, argv, ctx, action_cmd_perfcnt_mta_hif_cfg_get, cmd_perfcnt_mta_hif_cfg_get_options,
      "cxl perfcnt_mta_hif_cfg_get <mem0> [<mem1>..<memN>] [<options>]");

  return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_perfcnt_mta_hif_latch_val_get(int argc, const char **argv, struct cxl_ctx *ctx)
{
  int rc = memdev_action(argc, argv, ctx, action_cmd_perfcnt_mta_hif_latch_val_get, cmd_perfcnt_mta_hif_latch_val_get_options,
      "cxl perfcnt_mta_hif_latch_val_get <mem0> [<mem1>..<memN>] [<options>]");

  return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_perfcnt_mta_hif_counter_clear(int argc, const char **argv, struct cxl_ctx *ctx)
{
  int rc = memdev_action(argc, argv, ctx, action_cmd_perfcnt_mta_hif_counter_clear, cmd_perfcnt_mta_hif_counter_clear_options,
      "cxl perfcnt_mta_hif_counter_clear <mem0> [<mem1>..<memN>] [<options>]");

  return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_perfcnt_mta_hif_cnt_val_latch(int argc, const char **argv, struct cxl_ctx *ctx)
{
  int rc = memdev_action(argc, argv, ctx, action_cmd_perfcnt_mta_hif_cnt_val_latch, cmd_perfcnt_mta_hif_cnt_val_latch_options,
      "cxl perfcnt_mta_hif_cnt_val_latch <mem0> [<mem1>..<memN>] [<options>]");

  return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_perfcnt_ddr_generic_select(int argc, const char **argv, struct cxl_ctx *ctx)
{
  int rc = memdev_action(argc, argv, ctx, action_cmd_perfcnt_ddr_generic_select, cmd_perfcnt_ddr_generic_select_options,
      "cxl perfcnt_ddr_generic_select <mem0> [<mem1>..<memN>] [<options>]");

  return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_perfcnt_ddr_generic_capture(int argc, const char **argv, struct cxl_ctx *ctx)
{
	int rc = memdev_action(argc, argv, ctx, action_cmd_perfcnt_ddr_generic_capture, cmd_perfcnt_ddr_generic_capture_options,
			"cxl perfcnt_ddr_generic_capture <mem0> [<mem1>..<memN>] [<options>]");
	return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_perfcnt_ddr_dfi_capture(int argc, const char **argv, struct cxl_ctx *ctx)
{
	int rc = memdev_action(argc, argv, ctx, action_cmd_perfcnt_ddr_dfi_capture, cmd_perfcnt_ddr_dfi_capture_options,
			"cxl perfcnt_ddr_dfi_capture <mem0> [<mem1>..<memN>] [<options>]");
	return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_err_inj_drs_poison(int argc, const char **argv, struct cxl_ctx *ctx)
{
  int rc = memdev_action(argc, argv, ctx, action_cmd_err_inj_drs_poison, cmd_err_inj_drs_poison_options,
      "cxl err_inj_drs_poison <mem0> [<mem1>..<memN>] [<options>]");

  return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_err_inj_drs_ecc(int argc, const char **argv, struct cxl_ctx *ctx)
{
  int rc = memdev_action(argc, argv, ctx, action_cmd_err_inj_drs_ecc, cmd_err_inj_drs_ecc_options,
      "cxl err_inj_drs_ecc <mem0> [<mem1>..<memN>] [<options>]");

  return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_err_inj_rxflit_crc(int argc, const char **argv, struct cxl_ctx *ctx)
{
  int rc = memdev_action(argc, argv, ctx, action_cmd_err_inj_rxflit_crc, cmd_err_inj_rxflit_crc_options,
      "cxl err_inj_rxflit_crc <mem0> [<mem1>..<memN>] [<options>]");

  return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_err_inj_txflit_crc(int argc, const char **argv, struct cxl_ctx *ctx)
{
  int rc = memdev_action(argc, argv, ctx, action_cmd_err_inj_txflit_crc, cmd_err_inj_txflit_crc_options,
      "cxl err_inj_txflit_crc <mem0> [<mem1>..<memN>] [<options>]");

  return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_err_inj_viral(int argc, const char **argv, struct cxl_ctx *ctx)
{
  int rc = memdev_action(argc, argv, ctx, action_cmd_err_inj_viral, cmd_err_inj_viral_options,
      "cxl err_inj_viral <mem0> [<mem1>..<memN>] [<options>]");

  return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_eh_eye_cap_run(int argc, const char **argv, struct cxl_ctx *ctx)
{
  int rc = memdev_action(argc, argv, ctx, action_cmd_eh_eye_cap_run, cmd_eh_eye_cap_run_options,
      "cxl eh_eye_cap_run <mem0> [<mem1>..<memN>] [<options>]");

  return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_eh_eye_cap_read(int argc, const char **argv, struct cxl_ctx *ctx)
{
       int rc = memdev_action(argc, argv, ctx, action_cmd_eh_eye_cap_read, cmd_eh_eye_cap_read_options,
                       "cxl eh_eye_cap_read <mem0> [<mem1>..<memN>] [<options>]");

       return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_eh_eye_cap_timeout_enable(int argc, const char **argv, struct cxl_ctx *ctx)
{
       int rc = memdev_action(argc, argv, ctx, action_cmd_eh_eye_cap_timeout_enable, cmd_eh_eye_cap_timeout_enable_options,
                       "cxl eh-eye-cap-timeout-enable <mem0> [<mem1>..<memN>] [<options>]");

       return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_eh_eye_cap_status(int argc, const char **argv, struct cxl_ctx *ctx)
{
       int rc = memdev_action(argc, argv, ctx, action_cmd_eh_eye_cap_status, cmd_eh_eye_cap_status_options,
                       "cxl eh-eye-cap-status <mem0> [<mem1>..<memN>] [<options>]");

       return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_eh_adapt_get(int argc, const char **argv, struct cxl_ctx *ctx)
{
       int rc = memdev_action(argc, argv, ctx, action_cmd_eh_adapt_get, cmd_eh_adapt_get_options,
                       "cxl eh_adapt_get <mem0> [<mem1>..<memN>] [<options>]");

       return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_eh_adapt_oneoff(int argc, const char **argv, struct cxl_ctx *ctx)
{
       int rc = memdev_action(argc, argv, ctx, action_cmd_eh_adapt_oneoff, cmd_eh_adapt_oneoff_options,
                       "cxl eh_adapt_oneoff <mem0> [<mem1>..<memN>] [<options>]");

       return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_eh_adapt_force(int argc, const char **argv, struct cxl_ctx *ctx)
{
       int rc = memdev_action(argc, argv, ctx, action_cmd_eh_adapt_force, cmd_eh_adapt_force_options,
                       "cxl eh_adapt_force <mem0> [<mem1>..<memN>] [<options>]");

       return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_hbo_status(int argc, const char **argv, struct cxl_ctx *ctx)
{
       int rc = memdev_action(argc, argv, ctx, action_cmd_hbo_status, cmd_hbo_status_options,
                       "cxl hbo_status <mem0> [<mem1>..<memN>] [<options>]");

       return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_hbo_transfer_fw(int argc, const char **argv, struct cxl_ctx *ctx)
{
       int rc = memdev_action(argc, argv, ctx, action_cmd_hbo_transfer_fw, cmd_hbo_transfer_fw_options,
                       "cxl hbo_transfer_fw <mem0> [<mem1>..<memN>] [<options>]");

       return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_hbo_activate_fw(int argc, const char **argv, struct cxl_ctx *ctx)
{
  int rc = memdev_action(argc, argv, ctx, action_cmd_hbo_activate_fw, cmd_hbo_activate_fw_options,
      "cxl hbo_activate_fw <mem0> [<mem1>..<memN>] [<options>]");

  return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_health_counters_clear(int argc, const char **argv, struct cxl_ctx *ctx)
{
  int rc = memdev_action(argc, argv, ctx, action_cmd_health_counters_clear, cmd_health_counters_clear_options,
      "cxl health_counters_clear <mem0> [<mem1>..<memN>] [<options>]");

  return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_health_counters_get(int argc, const char **argv, struct cxl_ctx *ctx)
{
  int rc = memdev_action(argc, argv, ctx, action_cmd_health_counters_get, cmd_health_counters_get_options,
      "cxl health_counters_get <mem0> [<mem1>..<memN>] [<options>]");

  return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_hct_get_plat_param(int argc, const char **argv, struct cxl_ctx *ctx)
{
  int rc = memdev_action(argc, argv, ctx, action_cmd_hct_get_plat_param, cmd_hct_get_plat_param_options,
      "cxl hct-get-plat-params <mem0> [<mem1>..<memN>] [<options>]");

  return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_err_inj_hif_poison(int argc, const char **argv, struct cxl_ctx *ctx)
{
	int rc = memdev_action(argc, argv, ctx, action_cmd_err_inj_hif_poison, cmd_err_inj_hif_poison_options,
			"cxl err_inj_hif_poison <mem0> [<mem1>..<memN>] [<options>]");

	return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_err_inj_hif_ecc(int argc, const char **argv, struct cxl_ctx *ctx)
{
	int rc = memdev_action(argc, argv, ctx, action_cmd_err_inj_hif_ecc, cmd_err_inj_hif_ecc_options,
			"cxl err_inj_hif_ecc <mem0> [<mem1>..<memN>] [<options>]");

	return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_eh_link_dbg_cfg(int argc, const char **argv, struct cxl_ctx *ctx)
{
	int rc = memdev_action(argc, argv, ctx, action_cmd_eh_link_dbg_cfg, cmd_eh_link_dbg_cfg_options,
			"cxl eh-link-dbg-cfg <mem0> [<mem1>..<memN>] [<options>]");

	return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_eh_link_dbg_entry_dump(int argc, const char **argv, struct cxl_ctx *ctx)
{
	int rc = memdev_action(argc, argv, ctx, action_cmd_eh_link_dbg_entry_dump, cmd_eh_link_dbg_entry_dump_options,
			"cxl eh-link-dbg-entry-dump <mem0> [<mem1>..<memN>] [<options>]");

	return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_eh_link_dbg_lane_dump(int argc, const char **argv, struct cxl_ctx *ctx)
{
	int rc = memdev_action(argc, argv, ctx, action_cmd_eh_link_dbg_lane_dump, cmd_eh_link_dbg_lane_dump_options,
			"cxl eh-link-dbg-lane-dump <mem0> [<mem1>..<memN>] [<options>]");

	return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_eh_link_dbg_reset(int argc, const char **argv, struct cxl_ctx *ctx)
{
	int rc = memdev_action(argc, argv, ctx, action_cmd_eh_link_dbg_reset, cmd_eh_link_dbg_reset_options,
			"cxl eh-link-dbg-reset <mem0> [<mem1>..<memN>] [<options>]");

	return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_fbist_stopconfig_set(int argc, const char **argv, struct cxl_ctx *ctx)
{
	int rc = memdev_action(argc, argv, ctx, action_cmd_fbist_stopconfig_set, cmd_fbist_stopconfig_set_options,
			"cxl fbist_stopconfig_set <mem0> [<mem1>..<memN>] [<options>]");

	return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_fbist_cyclecount_set(int argc, const char **argv, struct cxl_ctx *ctx)
{
	int rc = memdev_action(argc, argv, ctx, action_cmd_fbist_cyclecount_set, cmd_fbist_cyclecount_set_options,
			"cxl fbist_cyclecount_set <mem0> [<mem1>..<memN>] [<options>]");

	return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_fbist_reset_set(int argc, const char **argv, struct cxl_ctx *ctx)
{
	int rc = memdev_action(argc, argv, ctx, action_cmd_fbist_reset_set, cmd_fbist_reset_set_options,
			"cxl fbist_reset_set <mem0> [<mem1>..<memN>] [<options>]");

	return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_fbist_run_set(int argc, const char **argv, struct cxl_ctx *ctx)
{
	int rc = memdev_action(argc, argv, ctx, action_cmd_fbist_run_set, cmd_fbist_run_set_options,
			"cxl fbist_run_set <mem0> [<mem1>..<memN>] [<options>]");

	return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_fbist_run_get(int argc, const char **argv, struct cxl_ctx *ctx)
{
	int rc = memdev_action(argc, argv, ctx, action_cmd_fbist_run_get, cmd_fbist_run_get_options,
			"cxl fbist_run_get <mem0> [<mem1>..<memN>] [<options>]");

	return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_fbist_xfer_rem_cnt_get(int argc, const char **argv, struct cxl_ctx *ctx)
{
	int rc = memdev_action(argc, argv, ctx, action_cmd_fbist_xfer_rem_cnt_get, cmd_fbist_xfer_rem_cnt_get_options,
			"cxl fbist_xfer_rem_cnt_get <mem0> [<mem1>..<memN>] [<options>]");

	return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_fbist_last_exp_read_data_get(int argc, const char **argv, struct cxl_ctx *ctx)
{
	int rc = memdev_action(argc, argv, ctx, action_cmd_fbist_last_exp_read_data_get, cmd_fbist_last_exp_read_data_get_options,
			"cxl fbist_last_exp_read_data_get <mem0> [<mem1>..<memN>] [<options>]");

	return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_fbist_curr_cycle_cnt_get(int argc, const char **argv, struct cxl_ctx *ctx)
{
	int rc = memdev_action(argc, argv, ctx, action_cmd_fbist_curr_cycle_cnt_get, cmd_fbist_curr_cycle_cnt_get_options,
			"cxl fbist_curr_cycle_cnt_get <mem0> [<mem1>..<memN>] [<options>]");

	return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_fbist_thread_status_get(int argc, const char **argv, struct cxl_ctx *ctx)
{
	int rc = memdev_action(argc, argv, ctx, action_cmd_fbist_thread_status_get, cmd_fbist_thread_status_get_options,
			"cxl fbist_thread_status_get <mem0> [<mem1>..<memN>] [<options>]");

	return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_fbist_thread_trans_cnt_get(int argc, const char **argv, struct cxl_ctx *ctx)
{
	int rc = memdev_action(argc, argv, ctx, action_cmd_fbist_thread_trans_cnt_get, cmd_fbist_thread_trans_cnt_get_options,
			"cxl fbist_thread_trans_cnt_get <mem0> [<mem1>..<memN>] [<options>]");

	return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_fbist_thread_bandwidth_get(int argc, const char **argv, struct cxl_ctx *ctx)
{
	int rc = memdev_action(argc, argv, ctx, action_cmd_fbist_thread_bandwidth_get, cmd_fbist_thread_bandwidth_get_options,
			"cxl fbist_thread_bandwidth_get <mem0> [<mem1>..<memN>] [<options>]");

	return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_fbist_thread_latency_get(int argc, const char **argv, struct cxl_ctx *ctx)
{
	int rc = memdev_action(argc, argv, ctx, action_cmd_fbist_thread_latency_get, cmd_fbist_thread_latency_get_options,
			"cxl fbist_thread_latency_get <mem0> [<mem1>..<memN>] [<options>]");

	return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_fbist_thread_perf_mon_set(int argc, const char **argv, struct cxl_ctx *ctx)
{
	int rc = memdev_action(argc, argv, ctx, action_cmd_fbist_thread_perf_mon_set, cmd_fbist_thread_perf_mon_set_options,
			"cxl fbist_thread_perf_mon_set <mem0> [<mem1>..<memN>] [<options>]");

	return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_fbist_top_read_status0_get(int argc, const char **argv, struct cxl_ctx *ctx)
{
	int rc = memdev_action(argc, argv, ctx, action_cmd_fbist_top_read_status0_get, cmd_fbist_top_read_status0_get_options,
			"cxl fbist_top_read_status0_get <mem0> [<mem1>..<memN>] [<options>]");

	return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_fbist_top_err_cnt_get(int argc, const char **argv, struct cxl_ctx *ctx)
{
	int rc = memdev_action(argc, argv, ctx, action_cmd_fbist_top_err_cnt_get, cmd_fbist_top_err_cnt_get_options,
			"cxl fbist_top_err_cnt_get <mem0> [<mem1>..<memN>] [<options>]");

	return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_fbist_last_read_addr_get(int argc, const char **argv, struct cxl_ctx *ctx)
{
	int rc = memdev_action(argc, argv, ctx, action_cmd_fbist_last_read_addr_get, cmd_fbist_last_read_addr_get_options,
			"cxl fbist_last_read_addr_get <mem0> [<mem1>..<memN>] [<options>]");

	return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_fbist_test_simpledata(int argc, const char **argv, struct cxl_ctx *ctx)
{
	int rc = memdev_action(argc, argv, ctx, action_cmd_fbist_test_simpledata, cmd_fbist_test_simpledata_options,
			"cxl fbist_test_simpledata <mem0> [<mem1>..<memN>] [<options>]");

	return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_fbist_test_addresstest(int argc, const char **argv, struct cxl_ctx *ctx)
{
	int rc = memdev_action(argc, argv, ctx, action_cmd_fbist_test_addresstest, cmd_fbist_test_addresstest_options,
			"cxl fbist_test_addresstest <mem0> [<mem1>..<memN>] [<options>]");

	return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_fbist_test_movinginversion(int argc, const char **argv, struct cxl_ctx *ctx)
{
	int rc = memdev_action(argc, argv, ctx, action_cmd_fbist_test_movinginversion, cmd_fbist_test_movinginversion_options,
			"cxl fbist_test_movinginversion <mem0> [<mem1>..<memN>] [<options>]");

	return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_fbist_test_randomsequence(int argc, const char **argv, struct cxl_ctx *ctx)
{
	int rc = memdev_action(argc, argv, ctx, action_cmd_fbist_test_randomsequence, cmd_fbist_test_randomsequence_options,
			"cxl fbist_test_randomsequence <mem0> [<mem1>..<memN>] [<options>]");

	return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_conf_read(int argc, const char **argv, struct cxl_ctx *ctx)
{
	int rc = memdev_action(argc, argv, ctx, action_cmd_conf_read, cmd_conf_read_options,
			"cxl conf_read <mem0> [<mem1>..<memN>] [<options>]");

	return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_hct_get_config(int argc, const char **argv, struct cxl_ctx *ctx)
{
	int rc = memdev_action(argc, argv, ctx, action_cmd_hct_get_config, cmd_hct_get_config_options,
			"cxl hct_get_config <mem0> [<mem1>..<memN>] [<options>]");

	return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_hct_read_buffer(int argc, const char **argv, struct cxl_ctx *ctx)
{
	int rc = memdev_action(argc, argv, ctx, action_cmd_hct_read_buffer, cmd_hct_read_buffer_options,
			"cxl hct_read_buffer <mem0> [<mem1>..<memN>] [<options>]");

	return rc >= 0 ? 0 : EXIT_FAILURE;
}

int cmd_hct_set_config(int argc, const char **argv, struct cxl_ctx *ctx)
{
	int rc = memdev_action(argc, argv, ctx, action_cmd_hct_set_config, cmd_hct_set_config_options,
			"cxl hct_set_config <mem0> [<mem1>..<memN>] [<options>]");

	return rc >= 0 ? 0 : EXIT_FAILURE;
}

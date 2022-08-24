/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (C) 2020-2021 Intel Corporation. All rights reserved. */
#ifndef _CXL_BUILTIN_H_
#define _CXL_BUILTIN_H_

struct cxl_ctx;
int cmd_update_fw(int argc, const char **argv, struct cxl_ctx *ctx);
int cmd_get_fw_info(int argc, const char **argv, struct cxl_ctx *ctx);
int cmd_transfer_fw(int argc, const char **argv, struct cxl_ctx *ctx);
int cmd_activate_fw(int argc, const char **argv, struct cxl_ctx *ctx);
int cmd_device_info_get(int argc, const char **argv, struct cxl_ctx *ctx);
int cmd_list(int argc, const char **argv, struct cxl_ctx *ctx);
int cmd_write_labels(int argc, const char **argv, struct cxl_ctx *ctx);
int cmd_read_labels(int argc, const char **argv, struct cxl_ctx *ctx);
int cmd_zero_labels(int argc, const char **argv, struct cxl_ctx *ctx);
int cmd_init_labels(int argc, const char **argv, struct cxl_ctx *ctx);
int cmd_check_labels(int argc, const char **argv, struct cxl_ctx *ctx);
int cmd_identify(int argc, const char **argv, struct cxl_ctx *ctx);
int cmd_get_supported_logs(int argc, const char **argv, struct cxl_ctx *ctx);
int cmd_get_cel_log(int argc, const char **argv, struct cxl_ctx *ctx);
int cmd_get_event_interrupt_policy(int argc, const char **argv, struct cxl_ctx *ctx);
int cmd_set_event_interrupt_policy(int argc, const char **argv, struct cxl_ctx *ctx);
int cmd_get_timestamp(int argc, const char **argv, struct cxl_ctx *ctx);
int cmd_set_timestamp(int argc, const char **argv, struct cxl_ctx *ctx);
int cmd_get_alert_config(int argc, const char **argv, struct cxl_ctx *ctx);
int cmd_set_alert_config(int argc, const char **argv, struct cxl_ctx *ctx);
int cmd_get_health_info(int argc, const char **argv, struct cxl_ctx *ctx);
int cmd_get_event_records(int argc, const char **argv, struct cxl_ctx *ctx);
int cmd_get_ld_info(int argc, const char **argv, struct cxl_ctx *ctx);
int cmd_clear_event_records(int argc, const char **argv, struct cxl_ctx *ctx);
int cmd_ddr_info(int argc, const char **argv, struct cxl_ctx *ctx);
int cmd_hct_start_stop_trigger(int argc, const char **argv, struct cxl_ctx *ctx);
int cmd_hct_get_buffer_status(int argc, const char **argv, struct cxl_ctx *ctx);
int cmd_hct_enable(int argc, const char **argv, struct cxl_ctx *ctx);
int cmd_ltmon_capture_clear(int argc, const char **argv, struct cxl_ctx *ctx);
int cmd_ltmon_capture(int argc, const char **argv, struct cxl_ctx *ctx);
int cmd_ltmon_capture_freeze_and_restore(int argc, const char **argv, struct cxl_ctx *ctx);
int cmd_ltmon_l2r_count_dump(int argc, const char **argv, struct cxl_ctx *ctx);
int cmd_ltmon_l2r_count_clear(int argc, const char **argv, struct cxl_ctx *ctx);
int cmd_ltmon_basic_cfg(int argc, const char **argv, struct cxl_ctx *ctx);
int cmd_ltmon_watch(int argc, const char **argv, struct cxl_ctx *ctx);
int cmd_ltmon_capture_stat(int argc, const char **argv, struct cxl_ctx *ctx);
int cmd_ltmon_capture_log_dmp(int argc, const char **argv, struct cxl_ctx *ctx);
int cmd_ltmon_capture_trigger(int argc, const char **argv, struct cxl_ctx *ctx);
int cmd_ltmon_enable(int argc, const char **argv, struct cxl_ctx *ctx);
int cmd_osa_os_type_trig_cfg(int argc, const char **argv, struct cxl_ctx *ctx);
int cmd_osa_cap_ctrl(int argc, const char **argv, struct cxl_ctx *ctx);
int cmd_osa_cfg_dump(int argc, const char **argv, struct cxl_ctx *ctx);
int cmd_osa_ana_op(int argc, const char **argv, struct cxl_ctx *ctx);
int cmd_osa_status_query(int argc, const char **argv, struct cxl_ctx *ctx);
int cmd_osa_access_rel(int argc, const char **argv, struct cxl_ctx *ctx);
int cmd_perfcnt_mta_ltif_set(int argc, const char **argv, struct cxl_ctx *ctx);
int cmd_perfcnt_mta_get(int argc, const char **argv, struct cxl_ctx *ctx);
int cmd_perfcnt_mta_latch_val_get(int argc, const char **argv, struct cxl_ctx *ctx);
int cmd_perfcnt_mta_counter_clear(int argc, const char **argv, struct cxl_ctx *ctx);
int cmd_perfcnt_mta_cnt_val_latch(int argc, const char **argv, struct cxl_ctx *ctx);
int cmd_perfcnt_mta_hif_set(int argc, const char **argv, struct cxl_ctx *ctx);
int cmd_perfcnt_mta_hif_cfg_get(int argc, const char **argv, struct cxl_ctx *ctx);
int cmd_perfcnt_mta_hif_latch_val_get(int argc, const char **argv, struct cxl_ctx *ctx);
int cmd_perfcnt_mta_hif_counter_clear(int argc, const char **argv, struct cxl_ctx *ctx);
int cmd_perfcnt_mta_hif_cnt_val_latch(int argc, const char **argv, struct cxl_ctx *ctx);
int cmd_perfcnt_ddr_generic_select(int argc, const char **argv, struct cxl_ctx *ctx);
int cmd_err_inj_drs_poison(int argc, const char **argv, struct cxl_ctx *ctx);
int cmd_err_inj_drs_ecc(int argc, const char **argv, struct cxl_ctx *ctx);
int cmd_err_inj_rxflit_crc(int argc, const char **argv, struct cxl_ctx *ctx);
int cmd_err_inj_txflit_crc(int argc, const char **argv, struct cxl_ctx *ctx);
int cmd_err_inj_viral(int argc, const char **argv, struct cxl_ctx *ctx);
int cmd_err_inj_hif_poison(int argc, const char **argv, struct cxl_ctx *ctx);
int cmd_eh_eye_cap_run(int argc, const char **argv, struct cxl_ctx *ctx);
int cmd_eh_eye_cap_read(int argc, const char **argv, struct cxl_ctx *ctx);
int cmd_eh_adapt_get(int argc, const char **argv, struct cxl_ctx *ctx);
int cmd_eh_adapt_oneoff(int argc, const char **argv, struct cxl_ctx *ctx);
int cmd_eh_adapt_force(int argc, const char **argv, struct cxl_ctx *ctx);
int cmd_hbo_status(int argc, const char **argv, struct cxl_ctx *ctx);
int cmd_hbo_transfer_fw(int argc, const char **argv, struct cxl_ctx *ctx);
int cmd_hbo_activate_fw(int argc, const char **argv, struct cxl_ctx *ctx);
int cmd_health_counters_clear(int argc, const char **argv, struct cxl_ctx *ctx);
int cmd_health_counters_get(int argc, const char **argv, struct cxl_ctx *ctx);
int cmd_hct_get_plat_param(int argc, const char **argv, struct cxl_ctx *ctx);
#endif /* _CXL_BUILTIN_H_ */

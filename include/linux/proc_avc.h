/*
 *  linux/include/linux/proc_avc.h
 *
 */

extern int __init sec_avc_log_init(void);
extern void sec_avc_log(char *fmt, ...);
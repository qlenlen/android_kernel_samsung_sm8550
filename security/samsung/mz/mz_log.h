#ifndef MZ_LOG_H
#define MZ_LOG_H

#ifndef LOG_TAG
#define LOG_TAG "MZ"
#endif // ifndef LOG_TAG

typedef enum _err_reporting_level_t {
	err_level_debug,
	err_level_info,
	err_level_error
} err_reporting_level_t;

void mz_write_to_log(uint32_t prio, const char *tag, const char *fmt, ...);

#define MZ_LOG(prio, format, ...) mz_write_to_log(prio, LOG_TAG, format, ## __VA_ARGS__)

#endif // MZ_LOG_H

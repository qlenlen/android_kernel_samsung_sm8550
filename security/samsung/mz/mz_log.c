#include <linux/kernel.h>
#include "mz_log.h"

#define LOG_BUF_SIZE         (128 + 100)

void mz_write_to_log(uint32_t prio, const char *tag, const char *fmt, ...)
{
	va_list ap;
	int32_t len = 0;
	char buf[LOG_BUF_SIZE];
	int written_amount;

	if (NULL == tag || NULL == fmt)
		return;

	switch (prio) {
	case err_level_debug:
#ifndef MZ_DEBUG
		return;
#endif
		len = snprintf(buf, LOG_BUF_SIZE, "%s_D ", tag); break;

	case err_level_info:
		len = snprintf(buf, LOG_BUF_SIZE, "%s_I ", tag); break;

	case err_level_error:
		len = snprintf(buf, LOG_BUF_SIZE, "%s_E ", tag); break;

	default:
		len = snprintf(buf, LOG_BUF_SIZE, "%s ", tag);
		break;
	}

	if ((len < 0) || (LOG_BUF_SIZE - len < len))
		return;

	va_start(ap, fmt);
	written_amount = vsnprintf(buf + len, LOG_BUF_SIZE - len, fmt, ap);
	va_end(ap);

	if (written_amount < 0)
		return;

	switch (prio) {
	case err_level_debug:
		pr_debug("%s", buf); break;

	case err_level_info:
		pr_info("%s", buf); break;

	case err_level_error:
		pr_err("%s", buf); break;

	default:
		pr_info("%s", buf);
		break;
	}
}

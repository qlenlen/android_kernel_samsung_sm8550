/* SPDX-License-Identifier: GPL-2.0 */
/*
 * C++ stream style string formatter and printer used in KUnit for outputting
 * KUnit messages.
 *
 * Copyright (C) 2019, Google LLC.
 * Author: Mike Krinkin <krinkin@google.com>
 */
#include <linux/types.h>

/**
 * strerror() - returns a string representation for the given error code.
 * @errno: an error code defined in include/uapi/asm-generic/errno-base.h or
 * include/uapi/asm-generic/errno.h
 *
 * This function returns mnemonic representation of error code (for example,
 * EPERM, ENOENT, ESRCH, etc). For unsupported errors this function returns
 * NULL.
 */
const char *strerror_str(int errno);

/**
 * strerror_r() - returns a string representation of the given error code.
 * Unlike strerror() it may use provided buffer to store the string, so in
 * the case of unknown error it returns a message containing an error code
 * instead of returning NULL.
 * @errno: an error code defined in include/uapi/asm-generic/errno-base.h or
 * include/uapi/asm-generic/errno.h
 * @buf: pointer to a buffer that could be used to store the string.
 * @buflen: contains the capacity of the buffer
 *
 * When function uses provided buffer and it's capacity is not enough to
 * store the whole string the string is truncated and always contains '\0'.
 * If buflen == 0, the function returns NULL pointer as there is not enough
 * space to store even '\0'.
 */
const char *strerror_r(int errno, char *buf, size_t buflen);

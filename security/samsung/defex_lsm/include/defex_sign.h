/*
 * Copyright (c) 2018 Samsung Electronics Co., Ltd. All Rights Reserved
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
*/

#ifndef __DEFEX_SIGN_H
#define __DEFEX_SIGN_H

#define SIGN_SIZE		256

int defex_rules_signature_check(const char *rules_buffer, unsigned int rules_data_size, unsigned int *rules_size);

#endif /* __DEFEX_SIGN_H */

/*
 * Copyright (c) 2018 Samsung Electronics Co., Ltd.
 *
 * Domain Filter Module:Implementation.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#ifndef _XT_DOMAINFILTER_MATCH_H
#define _XT_DOMAINFILTER_MATCH_H

#include <linux/types.h>

enum {
	XT_DOMAINFILTER_WHITE    = 1 << 0,
	XT_DOMAINFILTER_BLACK    = 1 << 1,

	XT_DOMAINFILTER_NAME_LEN  = 256, // lenght of a domain name
};

struct xt_domainfilter_match_info {
	char domain_name[XT_DOMAINFILTER_NAME_LEN];
	__u8 flags;
};

#endif //_XT_DOMAINFILTER_MATCH_H

/* PKCS #8 parser internal definitions
 *
 * Copyright (C) 2013 SUSE Linux Products GmbH. All rights reserved.
 * Written by Lee, Chun-Yi (jlee@suse.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#include <crypto/public_key.h>

struct pkcs8_info {
	enum pkey_algo privkey_algo:8;		/* Private key algorithm */
	struct private_key *priv;		/* Private key */
};

/*
 * pkcs8_parser.c
 */
extern void pkcs8_free_info(struct pkcs8_info *info);
extern struct pkcs8_info *pkcs8_info_parse(const void *data, size_t datalen);

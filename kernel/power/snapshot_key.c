// SPDX-License-Identifier: GPL-2.0

/* snapshot keys handler
 *
 * Copyright (C) 2018 Lee, Chun-Yi <jlee@suse.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#include <linux/cred.h>
#include <linux/key-type.h>
#include <linux/slab.h>
#include <crypto/hash.h>
#include <crypto/sha.h>
#include <keys/trusted-type.h>

#include "power.h"

static const char hash_alg[] = "sha512";
static struct crypto_shash *hash_tfm;

static struct snapshot_key {
	const char *key_name;
	struct key *key;
} skey = {
	.key_name = "swsusp-kmk",
	.key = NULL,
};

static int calc_hash(u8 *digest, const u8 *buf, unsigned int buflen,
		     bool may_sleep)
{
	SHASH_DESC_ON_STACK(desc, hash_tfm);
	int err;

	desc->tfm = hash_tfm;
	desc->flags = may_sleep ? CRYPTO_TFM_REQ_MAY_SLEEP : 0;

	err = crypto_shash_digest(desc, buf, buflen, digest);
	shash_desc_zero(desc);
	return err;
}

static int calc_key_hash(u8 *key, unsigned int key_len, const char *salt,
			 u8 *hash, bool may_sleep)
{
	unsigned int salted_buf_len;
	u8 *salted_buf;
 	int ret;
	print_hex_dump(KERN_INFO, "cal_key_hash: ", DUMP_PREFIX_NONE, 16, 1, key, key_len, 0);	//TODO: kill

	if (!key || !hash_tfm || !hash)
		return -EINVAL;

	salted_buf_len = strlen(salt) + 1 + SNAPSHOT_KEY_SIZE;
	salted_buf = kzalloc(salted_buf_len,
			may_sleep ? GFP_KERNEL : GFP_ATOMIC);
	if (!salted_buf)
		return -ENOMEM;

	strcpy(salted_buf, salt);
	memcpy(salted_buf + strlen(salted_buf) + 1, key, key_len);

	ret = calc_hash(hash, salted_buf, salted_buf_len, may_sleep);
	kzfree(salted_buf);

	return ret;
}

/* Derive authentication/encryption key */
static int get_derived_key(u8 *derived_key, const char *derived_type_str,
			   bool may_sleep)
{
	struct trusted_key_payload *tkp;
	int ret;

	if (!skey.key || !hash_tfm)
		return -EINVAL;

	down_read(&skey.key->sem);
	tkp = skey.key->payload.data[0];
	ret = calc_key_hash(tkp->key, tkp->key_len, derived_type_str,
				derived_key, may_sleep);
	up_read(&skey.key->sem);

 	return ret;
}

int snapshot_get_auth_key(u8 *auth_key, bool may_sleep)
{
	return get_derived_key(auth_key, "AUTH_KEY", may_sleep);
}

int snapshot_get_enc_key(u8 *enc_key, bool may_sleep)
{
	return get_derived_key(enc_key, "ENC_KEY", may_sleep);
}

/* this function may sleeps */
int snapshot_key_init(void)
{
	struct key *key;
	int err;

	pr_info("%s\n", __func__);

	if (skey.key)
		return 0;

	hash_tfm = crypto_alloc_shash(hash_alg, 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(hash_tfm)) {
		pr_err("snapshot key: can't allocate %s transform: %ld\n",
			hash_alg, PTR_ERR(hash_tfm));
		return PTR_ERR(hash_tfm);
	}

	/* find out swsusp-key */
	key = request_key(&key_type_trusted, skey.key_name, NULL);
	if (IS_ERR(key)) {
		pr_err("snapshot key: request key error: %ld\n", PTR_ERR(key));
		err = PTR_ERR(key);
		goto key_fail;
	}

	skey.key = key;

	return 0;

key_fail:
	crypto_free_shash(hash_tfm);
	hash_tfm = NULL;

	return err;
}

void snapshot_key_clean(void)
{
	crypto_free_shash(hash_tfm);
	hash_tfm = NULL;
	key_put(skey.key);
	skey.key = NULL;
}

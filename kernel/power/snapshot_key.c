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
#include <linux/efi.h>
#include <linux/key-type.h>
#include <linux/slab.h>
#include <keys/efi-type.h>
#include <crypto/hash.h>
#include <crypto/sha.h>

#include "power.h"

static const char hash_alg[] = "sha512";
static struct crypto_shash *hash_tfm;
static struct key *snapshot_key;

int get_encrypted_snapshot_key_blob(u8 *buffer)
{
	struct efi_key_payload *ekp;
	long len;

	pr_info("get_snapshot_key_encrypted_blob\n");
	if (!buffer)
		return -EINVAL;

	down_read(&snapshot_key->sem);
	ekp = snapshot_key->payload.data[0];

	/* read the encrypted key blob */
	len = efi_read_blob(snapshot_key, NULL, buffer, KEY_BLOB_BUFF_LEN);
	if (len < 0)
		pr_info("error: %ld\n", len);
	up_read(&snapshot_key->sem);

	/* TODO: request encrypted key */
	/* TODO: request swap header key */

	return len;
}

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

/* Derive authentication/encryption key from hibernate key */
static int get_derived_key(u8 *derived_key, const char *derived_type_str,
			   bool may_sleep)
{
	unsigned int derived_buf_len;
	struct efi_key_payload *ekp;
	u8 *derived_buf;
	int ret;

	if (!snapshot_key || !hash_tfm)
		return -EINVAL;

	derived_buf_len = strlen(derived_type_str) + 1 + SNAPSHOT_KEY_SIZE;
	derived_buf = kzalloc(derived_buf_len,
			may_sleep ? GFP_KERNEL : GFP_ATOMIC);
	if (!derived_buf)
		return -ENOMEM;

	strcpy(derived_buf, derived_type_str);
	down_read(&snapshot_key->sem);
	ekp = snapshot_key->payload.data[0];
	memcpy(derived_buf + strlen(derived_buf) + 1, ekp->key, ekp->key_len);
	up_read(&snapshot_key->sem);

	ret = calc_hash(derived_key, derived_buf, derived_buf_len, may_sleep);
	kzfree(derived_buf);

	return ret;
}

int get_snapshot_auth_key(u8 *auth_key, bool may_sleep)
{
	return get_derived_key(auth_key, "AUTH_KEY", may_sleep);
}

int get_snapshot_enc_key(u8 *enc_key, bool may_sleep)
{
	return get_derived_key(enc_key, "ENC_KEY", may_sleep);
}

/* this function may sleeps */
int init_snapshot_key(void)
{
	const struct cred *cred = current_cred();
	struct key *key;
	char *data;
	int err;

	pr_info("%s\n", __func__);

	hash_tfm = crypto_alloc_shash(hash_alg, 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(hash_tfm)) {
		pr_err("snapshot key: can't allocate %s transform: %ld\n",
			hash_alg, PTR_ERR(hash_tfm));
		return PTR_ERR(hash_tfm);
	}

	/* create snapshot key */
	key = key_alloc(&key_type_efi, "snapshot-key",
			GLOBAL_ROOT_UID, GLOBAL_ROOT_GID, cred, 0,
			KEY_ALLOC_NOT_IN_QUOTA, NULL);
	if (IS_ERR(key)) {
		pr_err("snapshot key: allocation error: %ld\n", PTR_ERR(key));
		err = -ENOMEM;
		goto key_alloc_fail;
	}

	data = "new 64";    // TODO: use SNAPSHOT_KEY_SIZE to generate data string
	err = key_instantiate_and_link(key, data, strlen(data), NULL, NULL);
	if (err < 0) {
		pr_err("snapshot key: instantiate_and_link error: %d\n", err);
		goto key_instantiate_fail;
	}

	snapshot_key = key;

	return 0;

key_instantiate_fail:
	key_put(key);
	key = NULL;
key_alloc_fail:
	crypto_free_shash(hash_tfm);
	hash_tfm = NULL;

	return err;
}

/* this function may sleeps */
int init_snapshot_key_by_blob(u8 *encrypted_key_blob)
{
	const struct cred *cred = current_cred();
	struct key *key;
	char *buffer;
	int err;

	pr_info("%s\n", __func__);
	if (!encrypted_key_blob)
		return -EINVAL;

	hash_tfm = crypto_alloc_shash(hash_alg, 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(hash_tfm)) {
		pr_err("snapshot key: can't allocate %s transform: %ld\n",
			hash_alg, PTR_ERR(hash_tfm));
		return PTR_ERR(hash_tfm);
	}

	key = key_alloc(&key_type_efi, "snapshot-key",
			GLOBAL_ROOT_UID, GLOBAL_ROOT_GID, cred, 0,
			KEY_ALLOC_NOT_IN_QUOTA, NULL);
	if (IS_ERR(key)) {
		pr_err("snapshot key: allocation error: %ld\n", PTR_ERR(key));
		err = -ENOMEM;
		goto key_alloc_fail;
	}

	buffer = kzalloc(KEY_BLOB_BUFF_LEN + strlen("load "), GFP_KERNEL);
	if (!buffer) {
		err = -ENOMEM;
		goto buf_alloc_fail;
	}

	memcpy(buffer, "load ", strlen("load "));
	memcpy(buffer + strlen("load "), encrypted_key_blob, KEY_BLOB_BUFF_LEN);
	err = key_instantiate_and_link(key, buffer,
		KEY_BLOB_BUFF_LEN + strlen("load "), NULL, NULL);
	if (err < 0) {
		pr_err("snapshot key: instantiate_and_link error: %d\n", err);
		goto key_instantiate_fail;
	}
	kzfree(buffer);

	snapshot_key = key;

	return 0;

key_instantiate_fail:
	kzfree(buffer);
buf_alloc_fail:
	key_put(key);
	key = NULL;
key_alloc_fail:
	crypto_free_shash(hash_tfm);
	hash_tfm = NULL;

	return err;
}

void clean_snapshot_key(void)
{
	key_put(snapshot_key);
	crypto_free_shash(hash_tfm);
	snapshot_key = NULL;
	hash_tfm = NULL;
}

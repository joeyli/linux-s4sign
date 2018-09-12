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
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/cred.h>
#include <linux/key-type.h>
#include <linux/slab.h>
#include <crypto/hash.h>
#include <crypto/sha.h>
#include <keys/trusted-type.h>
#include <keys/user-type.h>

#include "power.h"

static const char hash_alg[] = "sha512";
static struct crypto_shash *hash_tfm;

/* The master key of snapshot */
static struct snapshot_key {
	const char *key_name;
	bool initialized;
	unsigned int key_len;
	unsigned long pfn;			/* pfn of keyblob */
	unsigned long addr_offset;		/* offset in page for keyblob */
	u8 key[SNAPSHOT_KEY_SIZE];
	u8 fingerprint[SHA512_DIGEST_SIZE];	/* fingerprint of keyblob */
} skey = {
	.key_name = "swsusp-kmk",
};

static void snapshot_key_clean(void)
{
	crypto_free_shash(hash_tfm);
	hash_tfm = NULL;
	skey.pfn = 0;
	skey.key_len = 0;
	skey.addr_offset = 0;
	memzero_explicit(skey.key, SNAPSHOT_KEY_SIZE);
	memzero_explicit(skey.fingerprint, SHA512_DIGEST_SIZE);
	skey.initialized = false;
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

static int calc_key_hash(u8 *key, unsigned int key_len, const char *salt,
			 u8 *hash, bool may_sleep)
{
	unsigned int salted_buf_len;
	u8 *salted_buf;
	int ret;

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
	memzero_explicit(salted_buf, salted_buf_len);
	kzfree(salted_buf);

	return ret;
}

static int get_key_fingerprint(u8 *fingerprint, u8 *key, unsigned int key_len,
				bool may_sleep)
{
	return calc_key_hash(key, key_len, "FINGERPRINT", fingerprint, may_sleep);
}

void snapshot_key_page_erase(unsigned long pfn, void *buff_addr)
{
	if (!skey.initialized || pfn != skey.pfn)
		return;

	/* erase key data from snapshot buffer page */
	if (!memcmp(skey.key, buff_addr + skey.addr_offset, skey.key_len)) {
		memzero_explicit(buff_addr + skey.addr_offset, skey.key_len);
		pr_info("Erased swsusp key in snapshot pages.\n");
	}
}

/* this function may sleeps because snapshot_key_init() */
void snapshot_key_trampoline_backup(struct trampoline *t)
{
	if (!t || snapshot_key_init())
		return;

	memcpy(t->snapshot_key, skey.key, skey.key_len);
}

/* Be called after snapshot image restored success */
void snapshot_key_trampoline_restore(struct trampoline *t)
{
	u8 fingerprint[SHA512_DIGEST_SIZE];

	if (!skey.initialized || !t)
		return;

	/* check key fingerprint before restore */
	get_key_fingerprint(fingerprint, t->snapshot_key, skey.key_len, true);
	if (memcmp(skey.fingerprint, fingerprint, SHA512_DIGEST_SIZE)) {
		pr_warn("Restored swsusp key failed, fingerprint mismatch.\n");
		snapshot_key_clean();
		return;
	}

	memcpy(skey.key, t->snapshot_key, skey.key_len);
	memzero_explicit(t->snapshot_key, SNAPSHOT_KEY_SIZE);
}

/* Derive authentication/encryption key */
static int get_derived_key(u8 *derived_key, const char *derived_type_str,
			   bool may_sleep)
{
	int ret;

	if (!skey.initialized || !hash_tfm)
		return -EINVAL;

	ret = calc_key_hash(skey.key, skey.key_len, derived_type_str,
				derived_key, may_sleep);

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

bool snapshot_key_initialized(void)
{
	return skey.initialized;
}

static bool invalid_key(u8 *key, unsigned int key_len)
{
	int i;

	if (!key || !key_len)
		return true;

	if (key_len > SNAPSHOT_KEY_SIZE) {
		pr_warn("Size of swsusp key more than: %d.\n",
			SNAPSHOT_KEY_SIZE);
		return true;
	}

	/* zero keyblob is invalid key */
	for (i = 0; i < key_len; i++) {
		if (key[i] != 0)
			return false;
	}
	pr_warn("The swsusp key should not be zero.\n");

	return true;
}

static int trusted_key_init(void)
{
	struct trusted_key_payload *tkp;
	struct key *key;
	int err;

	pr_debug("%s\n", __func__);

	/* find out swsusp-key */
	key = request_key(&key_type_trusted, skey.key_name, NULL);
	if (IS_ERR(key)) {
		pr_err("Request key error: %ld\n", PTR_ERR(key));
		err = PTR_ERR(key);
		return err;
	}

	down_write(&key->sem);
	tkp = key->payload.data[0];
	if (invalid_key(tkp->key, tkp->key_len)) {
		err = -EINVAL;
		goto key_invalid;
	}
	skey.key_len = tkp->key_len;
	memcpy(skey.key, tkp->key, tkp->key_len);
	/* burn the original key contents */
	memzero_explicit(tkp->key, tkp->key_len);

key_invalid:
	up_write(&key->sem);
	key_put(key);

	return err;
}

static int user_key_init(void)
{
	struct user_key_payload *ukp;
	struct key *key;
	int err = 0;

	pr_debug("%s\n", __func__);

	/* find out swsusp-key */
	key = request_key(&key_type_user, skey.key_name, NULL);
	if (IS_ERR(key)) {
		pr_err("Request key error: %ld\n", PTR_ERR(key));
		err = PTR_ERR(key);
		return err;
	}

	down_write(&key->sem);
	ukp = user_key_payload_locked(key);
	if (!ukp) {
		/* key was revoked before we acquired its semaphore */
		err = -EKEYREVOKED;
		goto key_invalid;
	}
	if (invalid_key(ukp->data, ukp->datalen)) {
		err = -EINVAL;
		goto key_invalid;
	}
	skey.key_len = ukp->datalen;
	memcpy(skey.key, ukp->data, ukp->datalen);
	/* burn the original key contents */
	memzero_explicit(ukp->data, ukp->datalen);

key_invalid:
	up_write(&key->sem);
	key_put(key);

	return err;
}

/* this function may sleeps */
int snapshot_key_init(void)
{
	int err;

	pr_debug("%s\n", __func__);

	if (skey.initialized)
		return 0;

	hash_tfm = crypto_alloc_shash(hash_alg, 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(hash_tfm)) {
		pr_err("Can't allocate %s transform: %ld\n",
			hash_alg, PTR_ERR(hash_tfm));
		return PTR_ERR(hash_tfm);
	}

	err = trusted_key_init();
	if (err)
		err = user_key_init();
	if (err)
		goto key_fail;

	skey.pfn = page_to_pfn(virt_to_page(skey.key));
	skey.addr_offset = (unsigned long) skey.key & ~PAGE_MASK;
	get_key_fingerprint(skey.fingerprint, skey.key, skey.key_len, true);
	skey.initialized = true;

	pr_info("Snapshot key is initialled.\n");
	pr_debug("Fingerprint %*phN\n", SHA512_DIGEST_SIZE, skey.fingerprint);

	return 0;

key_fail:
	crypto_free_shash(hash_tfm);
	hash_tfm = NULL;

	return err;
}

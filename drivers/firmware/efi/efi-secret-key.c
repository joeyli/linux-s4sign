/* EFI secret key
 *
 * Copyright (C) 2017 Lee, Chun-Yi <jlee@suse.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/efi.h>
#include <linux/memblock.h>
#include <linux/security.h>
#include <linux/slab.h>
#include <linux/kobject.h>
#include <linux/key-type.h>
#include <linux/parser.h>
#include <linux/random.h>
#include <keys/user-type.h>
#include <keys/efi-type.h>
#include <crypto/hash.h>
#include <crypto/sha.h>
#include <crypto/skcipher.h>
#include <linux/scatterlist.h>
#include <crypto/algapi.h>

static u64 efi_skey_setup;
static void *secret_key;		/* TODO: rename to efi root secret key, 32 bytes is enough? */
static bool skey_regen;

void __init parse_efi_secret_key_setup(u64 phys_addr, u32 data_len)
{
	struct setup_data *skey_setup_data;

	/* reserve secret key setup data, will copy and erase later */
	efi_skey_setup = phys_addr + sizeof(struct setup_data);
	memblock_reserve(efi_skey_setup, sizeof(struct efi_skey_setup_data));

	/* clean setup data */
	skey_setup_data = early_memremap(phys_addr, data_len);
	memset(skey_setup_data, 0, sizeof(struct setup_data));
	early_iounmap(skey_setup_data, data_len);
}

static void __init
print_efi_skey_setup_data(struct efi_skey_setup_data *skey_setup)
{
	pr_debug("EFI secret key detection status: %s 0x%lx\n",
		efi_status_to_str(skey_setup->detect_status),
		skey_setup->detect_status);
	pr_debug("EFI secret key getting status: %s 0x%lx\n",
		efi_status_to_str(skey_setup->final_status),
		skey_setup->final_status);
	pr_debug("EFI secret key size: %ld\n", skey_setup->key_size);

	if (skey_setup->final_status != EFI_SUCCESS) {
		pr_warn("EFI secret key getting failed: %s 0x%lx\n",
			efi_status_to_str(skey_setup->final_status),
			skey_setup->final_status);
	}
	if (skey_setup->key_size < SECRET_KEY_SIZE) {
		pr_warn(KERN_CONT "EFI secret key size %ld is less than %d.",
			skey_setup->key_size, SECRET_KEY_SIZE);
		pr_warn(KERN_CONT " Please regenerate secret key\n");
	}
}

struct key_type key_type_efi;

static const char hash_alg[] = "sha256";
static const char hmac_alg[] = "hmac(sha256)";
static struct crypto_shash *hash_tfm;
#define ERK_HASH_SIZE SHA256_DIGEST_SIZE
#define HMAC_HASH_SIZE SHA256_DIGEST_SIZE
#define DKEY_SIZE SHA256_DIGEST_SIZE

static int calc_hash(struct crypto_shash *tfm, const u8 *buf,
		     unsigned int buflen, u8 *digest)
{
	SHASH_DESC_ON_STACK(desc, tfm);
	int ret;

	desc->tfm = tfm;
	desc->flags = 0;

	ret = crypto_shash_digest(desc, buf, buflen, digest);
	shash_desc_zero(desc);

	return ret;
}

static int get_derived_key(const char *salt, u8 *derived_key)
{
	u8 *derived_buf;
	unsigned int derived_buf_len;
	int ret;

	derived_buf_len = strlen(salt) + 1 + SECRET_KEY_SIZE;
	if (derived_buf_len < DKEY_SIZE)
		derived_buf_len = DKEY_SIZE;

	derived_buf = kzalloc(derived_buf_len, GFP_KERNEL);
	if (!derived_buf)
		return -ENOMEM;

	memcpy(derived_buf + strlen(derived_buf) + 1, secret_key,
		SECRET_KEY_SIZE);
	ret = calc_hash(hash_tfm, derived_buf, derived_buf_len, derived_key);
	memzero_explicit(derived_buf, derived_buf_len);

	return ret;
}

static int calc_hmac(const u8 *buf, unsigned int buflen, u8 *digest)
{
	struct crypto_shash *tfm;
	u8 *auth_key;
	int ret;

	auth_key = kzalloc(DKEY_SIZE, GFP_KERNEL);
	if (!auth_key)
		return -ENOMEM;

	tfm = crypto_alloc_shash(hmac_alg, 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(tfm)) {
		pr_err("can't alloc %s transform: %ld\n",
		       hmac_alg, PTR_ERR(tfm));
		ret = PTR_ERR(tfm);
		goto tfm_fail;
	}

	ret = get_derived_key("AUTH_KEY", auth_key);
	if (ret)
		goto key_fail;

	ret = crypto_shash_setkey(tfm, auth_key, DKEY_SIZE);
	if (!ret)
		ret = calc_hash(tfm, buf, buflen, digest);

key_fail:
	crypto_free_shash(tfm);
tfm_fail:
	memzero_explicit(auth_key, DKEY_SIZE);

	return ret;
}

static const char blkcipher_alg[] = "cbc(aes)";
static unsigned int ivsize;
static int blksize;

static int set_aes_sizes(void)
{
	struct crypto_skcipher *tfm;

	tfm = crypto_alloc_skcipher(blkcipher_alg, 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(tfm)) {
		pr_err("failed to alloc_cipher (%ld)\n", PTR_ERR(tfm));
		return PTR_ERR(tfm);
	}
	ivsize = crypto_skcipher_ivsize(tfm);
	blksize = crypto_skcipher_blocksize(tfm);
	crypto_free_skcipher(tfm);

	return 0;
}

static int __init init_efi_secret_key(void)
{
	struct efi_skey_setup_data *skey_setup;
	int ret = 0;

	if (!efi_skey_setup)
		return -ENODEV;

	skey_setup = early_memremap(efi_skey_setup,
				    sizeof(struct efi_skey_setup_data));
	print_efi_skey_setup_data(skey_setup);
	secret_key = memcpy_to_hidden_area(skey_setup->secret_key,
					   SECRET_KEY_SIZE);
	if (!secret_key)
		pr_info("copy secret key to hidden area failed\n");

	/* earse key in setup data */
	memset(skey_setup->secret_key, 0, SECRET_KEY_SIZE);
	early_iounmap(skey_setup, sizeof(struct efi_skey_setup_data));

	hash_tfm = crypto_alloc_shash(hash_alg, 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(hash_tfm)) {
		pr_err("can't allocate %s transform: %ld\n",
			hash_alg, PTR_ERR(hash_tfm));
		return PTR_ERR(hash_tfm);
	}

	/* initial EFI key type */
	if (secret_key) {
		ret = set_aes_sizes();
		if (!ret)
			ret = register_key_type(&key_type_efi);
	}

	return ret;
}

void *get_efi_secret_key(void)
{
	return secret_key;
}
EXPORT_SYMBOL(get_efi_secret_key);

late_initcall(init_efi_secret_key);

static int set_regen_flag(void)
{
	struct efivar_entry *entry = NULL;
	bool regen = true;
	int err = 0;

	if (!efi_enabled(EFI_RUNTIME_SERVICES))
		return 0;

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return -ENOMEM;

	memcpy(entry->var.VariableName,
	       EFI_SECRET_KEY_REGEN, sizeof(EFI_SECRET_KEY_REGEN));
	memcpy(&(entry->var.VendorGuid),
	       &EFI_SECRET_GUID, sizeof(efi_guid_t));
	err = efivar_entry_set(entry, EFI_SECRET_KEY_REGEN_ATTRIBUTE,
			       sizeof(bool), &regen, NULL);
	if (err)
		pr_warn("Create EFI secret key regen failed: %d\n", err);

	kfree(entry);

	return err;
}

static int clean_regen_flag(void)
{
	struct efivar_entry *entry = NULL;
	int err = 0;

	if (!efi_enabled(EFI_RUNTIME_SERVICES))
		return 0;

	entry = kzalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return -ENOMEM;

	memcpy(entry->var.VariableName,
	       EFI_SECRET_KEY_REGEN, sizeof(EFI_SECRET_KEY_REGEN));
	memcpy(&(entry->var.VendorGuid),
	       &EFI_SECRET_GUID, sizeof(efi_guid_t));
	err = efivar_entry_set(entry, EFI_SECRET_KEY_REGEN_ATTRIBUTE,
			       0, NULL, NULL);
	if (err && err != -ENOENT)
		pr_warn("Clean EFI secret key regen failed: %d\n", err);

	kfree(entry);

	return err;
}

void efi_skey_stop_regen(void)
{
	if (!efi_enabled(EFI_RUNTIME_SERVICES))
		return;

	if (!clean_regen_flag())
		skey_regen = false;
}
EXPORT_SYMBOL(efi_skey_stop_regen);

static struct kobject *secret_key_kobj;

static ssize_t regen_show(struct kobject *kobj,
			  struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%d\n", skey_regen);
}

static ssize_t regen_store(struct kobject *kobj,
			   struct kobj_attribute *attr,
			   const char *buf, size_t size)
{
	bool regen_in;
	int ret;

	ret = strtobool(buf, &regen_in);
	if (ret < 0)
		return ret;

	if (!skey_regen && regen_in) {
		ret = set_regen_flag();
		if (ret < 0)
			return ret;
	}

	if (skey_regen && !regen_in) {
		ret = clean_regen_flag();
		if (ret < 0)
			return ret;
	}

	skey_regen = regen_in;

	return size;
}

static const struct kobj_attribute regen_attr =
	__ATTR(regen, 0644, regen_show, regen_store);

int __init efi_skey_sysfs_init(struct kobject *efi_kobj)
{
	secret_key_kobj = kobject_create_and_add("secret-key", efi_kobj);
	if (!secret_key_kobj)
		return -ENOMEM;

	return sysfs_create_file(secret_key_kobj, &regen_attr.attr);
}

enum {
	Opt_err = -1,
	Opt_new, Opt_load, Opt_update,
	/* TODO: Opt_update, */
};

static const match_table_t key_tokens = {
	{Opt_new, "new"},
	{Opt_load, "load"},
	{Opt_err, NULL}
};

static struct efi_key_payload *efi_payload_alloc(struct key *key, char *key_len_str)
{
	struct efi_key_payload *ekp = NULL;
	unsigned short encrypted_keylen;
	unsigned short datablob_len;
	unsigned short payload_len;
	long key_len;
	int ret;

	ret = kstrtol(key_len_str, 10, &key_len);
	if (ret < 0)
		return ERR_PTR(ret);
	encrypted_keylen = roundup(key_len, blksize);

	/* efi_key_payload + key + datablob + hmac */
	datablob_len = strlen(key_len_str) + 1 + ERK_HASH_SIZE + ivsize + encrypted_keylen;
	payload_len = sizeof(*ekp) + key_len + datablob_len + HMAC_HASH_SIZE;

	ret = key_payload_reserve(key, payload_len);
	if (ret < 0)
		return ERR_PTR(ret);

	ekp = kzalloc(payload_len, GFP_KERNEL);
	if (!ekp)
		return ERR_PTR(-ENOMEM);
	ekp->key = ekp->payload_data;
	ekp->datablob = ekp->key + key_len;
	ekp->key_len_str = ekp->datablob;
	ekp->erk_hash = ekp->key_len_str + strlen(key_len_str) + 1;
	ekp->iv = ekp->erk_hash + ERK_HASH_SIZE;
	ekp->encrypted_key = ekp->iv + ivsize;
	ekp->hmac = ekp->encrypted_key + encrypted_keylen;
	ekp->key_len = key_len;
	ekp->datablob_len = datablob_len;

	memcpy(ekp->key_len_str, key_len_str, strlen(key_len_str));

	return ekp;
}

/*
 * datablob_parse - parse the keyctl data and fill in the
 *                  payload and options structures
 *
 * On success returns command number, otherwise -EINVAL.
 */
static int datablob_parse(char *datablob, char **key_len_str, char **hex_encoded_blob)
{
	substring_t args[MAX_OPT_ARGS];
	long key_len;
	int key_cmd;
	int ret;
	char *c;

	/* main command */
	c = strsep(&datablob, " \t");
	if (!c)
		return -EINVAL;
	key_cmd = match_token(c, key_tokens, args);

	/* first string argument is key length */
	c = strsep(&datablob, " \t");
	if (!c)
		return -EINVAL;
	*key_len_str = c;
	ret = kstrtol(*key_len_str, 10, &key_len);
	if (ret < 0 || key_len < MIN_KEY_SIZE || key_len > MAX_KEY_SIZE)
		return -EINVAL;

	switch (key_cmd) {
	case Opt_new:
		ret = Opt_new;
		break;
	case Opt_load:
		*hex_encoded_blob = strsep(&datablob, " \t");
		if (!*hex_encoded_blob) {
			pr_info("hex blob is missing\n");
			return -EINVAL;
		}
		if (strlen(*hex_encoded_blob) / 2 > MAX_BLOB_SIZE)
			return -EINVAL;
		ret = Opt_load;
		break;
	case Opt_err:
		return -EINVAL;
	}

	return ret;
}

static int key_encrypt(struct efi_key_payload *ekp, size_t encrypted_keylen)
{
	struct scatterlist src[1], dst[1];
	struct crypto_skcipher *tfm;
	struct skcipher_request *req;
	u8 *encrypted_key_tmp;
	u8 *iv_tmp, *enc_key;
	int ret;

	encrypted_key_tmp = kzalloc(encrypted_keylen, GFP_KERNEL);
	if (!encrypted_key_tmp)
		return -ENOMEM;

	enc_key = kzalloc(DKEY_SIZE, GFP_KERNEL);
	if (!enc_key) {
		ret = -ENOMEM;
		goto key_fail;
	}

	iv_tmp = kmemdup(ekp->iv, ivsize, GFP_KERNEL);
	if (!iv_tmp) {
		ret = -ENOMEM;
		goto iv_fail;
	}

	tfm = crypto_alloc_skcipher(blkcipher_alg, 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(tfm)) {
		ret = PTR_ERR(tfm);
		pr_err("failed to allocate skcipher (%d)\n", ret);
		goto tfm_fail;
	}

	ret = get_derived_key("ENC_KEY", enc_key);
	if (ret) {
		pr_err("failed to get encrypt key\n");
		goto req_fail;
	}

	ret = crypto_skcipher_setkey(tfm, enc_key, DKEY_SIZE);
	if (ret) {
		pr_err("failed to setkey (%d)\n", ret);
		goto req_fail;
	}

	req = skcipher_request_alloc(tfm, GFP_KERNEL);
	if (!req) {
		pr_err("failed to allocate request\n");
		ret = -ENOMEM;
		goto req_fail;
	}

	memcpy(iv_tmp, ekp->iv, ivsize);
	sg_init_one(src, ekp->key, ekp->key_len);
	sg_init_one(dst, encrypted_key_tmp, encrypted_keylen);
	skcipher_request_set_crypt(req, src, dst, ekp->key_len, iv_tmp);
	ret = crypto_skcipher_encrypt(req);
	if (!ret)
		memcpy(ekp->encrypted_key, encrypted_key_tmp, encrypted_keylen);

	skcipher_request_free(req);
req_fail:
	crypto_free_skcipher(tfm);
tfm_fail:
	kzfree(iv_tmp);
iv_fail:
	memzero_explicit(enc_key, DKEY_SIZE);
key_fail:
	kzfree(encrypted_key_tmp);

	return ret;
}

static int key_decrypt(struct efi_key_payload *ekp)
{
	struct scatterlist src[1], dst[1];
	struct crypto_skcipher *tfm;
	struct skcipher_request *req;
	size_t encrypted_keylen;
	u8 *decrypted_key_tmp;
	u8 *enc_key, *iv_tmp;
	int ret;

	encrypted_keylen = roundup(ekp->key_len, blksize);

	decrypted_key_tmp = kzalloc(ekp->key_len, GFP_KERNEL);
	if (!decrypted_key_tmp)
		return -ENOMEM;

	enc_key = kzalloc(DKEY_SIZE, GFP_KERNEL);
	if (!enc_key) {
		ret = -ENOMEM;
		goto key_fail;
	}

	iv_tmp = kmemdup(ekp->iv, ivsize, GFP_KERNEL);
	if (!iv_tmp) {
		ret = -ENOMEM;
		goto iv_fail;
	}

	tfm = crypto_alloc_skcipher(blkcipher_alg, 0, CRYPTO_ALG_ASYNC);
	if (IS_ERR(tfm)) {
		ret = PTR_ERR(tfm);
		pr_err("failed to allocate skcipher (%d)\n", ret);
		goto tfm_fail;
	}

	ret = get_derived_key("ENC_KEY", enc_key);
	if (ret) {
		pr_err("failed to get encrypt key\n");
		goto req_fail;
	}

	ret = crypto_skcipher_setkey(tfm, enc_key, DKEY_SIZE);
	if (ret) {
		pr_err("failed to setkey (%d)\n", ret);
		goto req_fail;
	}

	req = skcipher_request_alloc(tfm, GFP_KERNEL);
	if (!req) {
		pr_err("failed to allocate request\n");
		ret = -ENOMEM;
		goto req_fail;
	}

	memcpy(iv_tmp, ekp->iv, ivsize);
	sg_init_one(src, ekp->encrypted_key, encrypted_keylen);
	sg_init_one(dst, decrypted_key_tmp, ekp->key_len);
	skcipher_request_set_crypt(req, src, dst, ekp->key_len, iv_tmp);
	ret = crypto_skcipher_decrypt(req);
	if (!ret)
		memcpy(ekp->key, decrypted_key_tmp, ekp->key_len);

	skcipher_request_free(req);
req_fail:
	crypto_free_skcipher(tfm);
tfm_fail:
	kzfree(iv_tmp);
iv_fail:
	memzero_explicit(enc_key, DKEY_SIZE);
key_fail:
	kzfree(decrypted_key_tmp);

	return ret;
}

/*
 * Convert the ascii encoded blob to binary. And checking the hmac.
 * The input blob format is:
 * <erk hash> <encrypted iv> <encrypted key> <hmac>
 */
static int verify_hmac(struct efi_key_payload *ekp, char *hex_encoded_blob)
{
	size_t encrypted_keylen;
	char *bufp;
	u8 *hmac;
	int ret;

	/* TODO: check blob size? */
//	if (strlen(hex_encoded_blob) / 2 > MAX_BLOB_SIZE)
	bufp = hex_encoded_blob;
	ret = hex2bin(ekp->erk_hash, bufp, ERK_HASH_SIZE);
	if (ret < 0)
		return -EINVAL;

	/* TODO: check the hash of EFI root key when update */

	bufp += ERK_HASH_SIZE * 2;
	ret = hex2bin(ekp->iv, bufp, ERK_HASH_SIZE);
	if (ret < 0)
		return -EINVAL;

	/* encrypted key */
	bufp += ivsize * 2;
	encrypted_keylen = roundup(ekp->key_len, blksize);
	ret = hex2bin(ekp->encrypted_key, bufp, encrypted_keylen);
	if (ret < 0)
		return -EINVAL;

	/* verify hmac */
	bufp += encrypted_keylen * 2;
	ret = hex2bin(ekp->hmac, bufp, HMAC_HASH_SIZE);
	if (ret < 0)
		return -EINVAL;

	hmac = kzalloc(HMAC_HASH_SIZE, GFP_KERNEL);
	if (!hmac)
		return -ENOMEM;

	ret = calc_hmac(ekp->datablob, ekp->datablob_len, hmac);
	if (ret)
		goto err;

	ret = crypto_memneq(ekp->hmac, hmac, HMAC_HASH_SIZE);
	if (ret) {
		pr_warn("hmac signature does not match\n");
		ret = -EINVAL;
	}

err:
	kzfree(hmac);
	return ret;
}

/*
 * efi_instantiate - create a new efi key
 *
 * Decrypt an existing efi key blob or, for a new key, get a
 * random key, then encrypt and creatse a efi key-type key,
 * adding it to the specified keyring.
 *
 * e.g.
 * keyctl add efi kmk-efi "new 128" @u
 * keyctl add efi kmk-efi "load `cat kmk-efi.blob`" @u
 *
 * On success, return 0. Otherwise return errno.
 */
static int efi_instantiate(struct key *key,
			   struct key_preparsed_payload *prep)
{
	struct efi_key_payload *ekp = NULL;
	size_t datalen = prep->datalen;
	char *datablob = NULL;
	char *key_len_str = NULL;
	char *hex_encoded_blob = NULL;
	int key_cmd;
	int ret = 0;

	/* TODO: check max datalen? 32k? */
	if (datalen <= 0 || datalen > 32767 || !prep->data)
		return -EINVAL;

	datablob = kzalloc(datalen + 1, GFP_KERNEL);
	if (!datablob)
		return -ENOMEM;
	memcpy(datablob, prep->data, datalen);
	datablob[datalen] = '\0';

	key_cmd = datablob_parse(datablob, &key_len_str, &hex_encoded_blob);
	if (key_cmd < 0) {
		ret = key_cmd;
		goto out;
	}

	ekp = efi_payload_alloc(key, key_len_str);
	if (!ekp) {
		ret = -ENOMEM;
		goto out;
	}

	switch (key_cmd) {
	case Opt_load:
		ret = verify_hmac(ekp, hex_encoded_blob);
		if (ret)
			break;
		ret = key_decrypt(ekp);
		break;
	case Opt_new:
		get_random_bytes(ekp->iv, ivsize);
		get_random_bytes(ekp->key, ekp->key_len);
		break;
	default:
		ret = -EINVAL;
		goto out;
	}
out:
	kzfree(datablob);
	if (!ret)
		rcu_assign_keypointer(key, ekp);
	else
		kzfree(ekp);
	return ret;
}

/*
 * efi_read_blob - copy the encrypted blob data to userspace in hex.
 *
 * The resulting datablob format is:
 * <key length string> <erk hash> <encrypted iv> <encrypted key> <hmac>
 *
 * On success, return to userspace the efi key datablob size.
 */
long efi_read_blob(const struct key *key, char __user *buffer,
		   char *kbuffer, size_t buflen)
{
	struct efi_key_payload *ekp;
	size_t asciiblob_len, encrypted_keylen;
	char *ascii_buf;
	char *bufp;
	int i, len;
	int ret;

	ekp = dereference_key_locked(key);
	if (!ekp)
		return -EINVAL;

	/* datablob_len = key_len string length + 1 + ERK hash length + ivsize + encrypted_keylen
	 * double size of ERK hash, iv, encrypted key, and hmac for ascii
	 */
	encrypted_keylen = roundup(ekp->key_len, blksize);
	asciiblob_len = ekp->datablob_len + ERK_HASH_SIZE + ivsize + encrypted_keylen + HMAC_HASH_SIZE * 2;

	if ((!buffer && !kbuffer) || buflen < asciiblob_len)
		return asciiblob_len;

	ascii_buf = kzalloc(asciiblob_len + 1, GFP_KERNEL);
	if (!ascii_buf)
		return -ENOMEM;

	ascii_buf[asciiblob_len] = '\0';

	/* copy key length string */
	len = sprintf(ascii_buf, "%d ", ekp->key_len);

	/* pack hash of ERK */
	bufp = ascii_buf + len;
	ret = calc_hash(hash_tfm, secret_key, SECRET_KEY_SIZE, ekp->erk_hash);
	if (ret)
		goto err;
	for (i = 0; i < ERK_HASH_SIZE; i++)
		bufp = hex_byte_pack(bufp, ekp->erk_hash[i]);

	/* pack iv */
	for (i = 0; i < ivsize; i++)
		bufp = hex_byte_pack(bufp, ekp->iv[i]);

	/* encrypt and pack key */
	ret = key_encrypt(ekp, encrypted_keylen);
	if (ret)
		goto err;
	for (i = 0; i < ekp->key_len; i++)
		bufp = hex_byte_pack(bufp, ekp->encrypted_key[i]);

	/* generate and pack HMAC */
	ret = calc_hmac(ekp->datablob, ekp->datablob_len, ekp->hmac);
	if (ret)
		goto err;
	for (i = 0; i < HMAC_HASH_SIZE; i++)
		bufp = hex_byte_pack(bufp, ekp->hmac[i]);

	ret = asciiblob_len;
	if (buffer) {
		if (copy_to_user(buffer, ascii_buf, asciiblob_len) != 0)
			ret = -EFAULT;
	}
	if (kbuffer) {
		if (!memcpy(kbuffer, ascii_buf, asciiblob_len))
			ret = -EFAULT;
	}
err:
	kzfree(ascii_buf);
	return ret;
}
EXPORT_SYMBOL(efi_read_blob);

/*
 * efi_read - format and copy the encrypted data to userspace
 *
 * The resulting datablob format is:
 * <key length string> <erk hash> <encrypted iv> <encrypted key> <hmac>
 *
 * On success, return to userspace the encrypted key datablob size.
 */
static long efi_read(const struct key *key, char __user *buffer,
			size_t buflen)
{
	return efi_read_blob(key, buffer, NULL, buflen);
}

/*
 * efi_destroy - clear and free the key's payload
 */
static void efi_destroy(struct key *key)
{
	kzfree(key->payload.data[0]);
}

struct key_type key_type_efi = {
	.name = "efi",
	.instantiate = efi_instantiate,
/* TODO:.update = efi_update,	*/
	.destroy = efi_destroy,
	.describe = user_describe,
	.read = efi_read,
};
EXPORT_SYMBOL_GPL(key_type_efi);

/*
 * request_efi_key - request the efi key
 */
struct key *request_efi_key(const char *master_desc,
			    const u8 **master_key, size_t *master_keylen)
{
	struct efi_key_payload *epayload;
	struct key *ekey;

	ekey = request_key(&key_type_efi, master_desc, NULL);
	if (IS_ERR(ekey))
		goto error;

	down_read(&ekey->sem);
	epayload = ekey->payload.data[0];
	*master_key = epayload->key;
	*master_keylen = epayload->key_len;
error:
	return ekey;
}

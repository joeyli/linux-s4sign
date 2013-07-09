/* Instantiate a private key crypto key
 *
 * Copyright (C) 2013 SUSE Linux Products GmbH. All rights reserved.
 * Written by Chun-Yi Lee (jlee@suse.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#define pr_fmt(fmt) "PKCS8: "fmt
#include <linux/module.h>
#include <linux/slab.h>
#include <keys/asymmetric-subtype.h>
#include <keys/asymmetric-parser.h>
#include <crypto/hash.h>
#include "private_key.h"
#include "pkcs8-asn1.h"
#include "pkcs8_parser.h"

#define KEY_PREFIX "Private Key: "
#define FINGERPRINT_HASH "sha256"

static const
struct private_key_algorithm *pkcs8_private_key_algorithms[PKEY_ALGO__LAST] = {
	[PKEY_ALGO_DSA]         = NULL,
#if defined(CONFIG_PUBLIC_KEY_ALGO_RSA) || \
	defined(CONFIG_PUBLIC_KEY_ALGO_RSA_MODULE)
	[PKEY_ALGO_RSA]         = &RSA_private_key_algorithm,
#endif
};

/*
 * Attempt to parse a data blob for a private key.
 */
static int pkcs8_key_preparse(struct key_preparsed_payload *prep)
{
	struct pkcs8_info *info;
	struct crypto_shash *tfm;
	struct shash_desc *desc;
	u8 *digest;
	size_t digest_size, desc_size;
	char *fingerprint, *description;
	int i, ret;

	pr_info("pkcs8_key_preparse start\n");

	info = pkcs8_info_parse(prep->data, prep->datalen);
	if (IS_ERR(info))
		return PTR_ERR(info);

	info->priv->algo = pkcs8_private_key_algorithms[info->pkey_algo];
	info->priv->id_type = PKEY_ID_PKCS8;

	/* Hash the pkcs #8 blob to generate fingerprint */
	tfm = crypto_alloc_shash(FINGERPRINT_HASH, 0, 0);
	if (IS_ERR(tfm)) {
		ret = PTR_ERR(tfm);
		goto error_shash;
	}
	desc_size = crypto_shash_descsize(tfm) + sizeof(*desc);
	digest_size = crypto_shash_digestsize(tfm);

	ret = -ENOMEM;

	digest = kzalloc(digest_size + desc_size, GFP_KERNEL);
	if (!digest)
		goto error_digest;
	desc = (void *) digest + digest_size;
	desc->tfm = tfm;
	desc->flags = CRYPTO_TFM_REQ_MAY_SLEEP;

	ret = crypto_shash_init(desc);
	if (ret < 0)
		goto error_shash_init;
	ret = crypto_shash_finup(desc, prep->data, prep->datalen, digest);
	if (ret < 0)
		goto error_shash_finup;

	fingerprint = kzalloc(digest_size * 2 + 1, GFP_KERNEL);
	if (!fingerprint)
		goto error_fingerprint;
	for (i = 0; i < digest_size; i++)
		sprintf(fingerprint + i * 2, "%02x", digest[i]);

	/* Propose a description */
	description = kzalloc(strlen(KEY_PREFIX) + strlen(fingerprint) + 1, GFP_KERNEL);
	if (!description)
		goto error_description;
	sprintf(description, "%s", KEY_PREFIX);
	memcpy(description + strlen(KEY_PREFIX), fingerprint, strlen(fingerprint));

	/* We're pinning the module by being linked against it */
	__module_get(private_key_subtype.owner);
	prep->type_data[0] = &private_key_subtype;
	prep->type_data[1] = fingerprint;
	prep->payload = info->priv;
	prep->description = description;

	/* size of 4096 bits private key file is 2.3K */
	prep->quotalen = 700;

	pr_info("pkcs8_key_preparse done\n");

	/* We've finished with the information */
	kfree(digest);
	crypto_free_shash(tfm);
	info->priv = NULL;
	pkcs8_free_info(info);

	return 0;

error_description:
	kfree(fingerprint);
error_fingerprint:
error_shash_finup:
error_shash_init:
	kfree(digest);
error_digest:
	crypto_free_shash(tfm);
error_shash:
	info->priv = NULL;
	pkcs8_free_info(info);
	return ret;
}

static struct asymmetric_key_parser pkcs8_private_key_parser = {
	.owner	= THIS_MODULE,
	.name	= "pkcs8",
	.parse	= pkcs8_key_preparse,
};

/*
 * Module stuff
 */
static int __init pkcs8_private_key_init(void)
{
	return register_asymmetric_key_parser(&pkcs8_private_key_parser);
}

static void __exit pkcs8_private_key_exit(void)
{
	unregister_asymmetric_key_parser(&pkcs8_private_key_parser);
}

module_init(pkcs8_private_key_init);
module_exit(pkcs8_private_key_exit);

/* Signature verification with an asymmetric key
 *
 * See Documentation/security/asymmetric-keys.txt
 *
 * Copyright (C) 2012 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#include <keys/asymmetric-subtype.h>
#include <linux/module.h>
#include <linux/err.h>
#include <crypto/public_key.h>
#include "asymmetric_keys.h"

/**
 * verify_signature - Initiate the use of an asymmetric key to verify a signature
 * @key: The asymmetric key to verify against
 * @sig: The signature to check
 *
 * Returns 0 if successful or else an error.
 */
int verify_signature(const struct key *key,
		     const struct public_key_signature *sig)
{
	const struct asymmetric_key_subtype *subtype;
	int ret;

	pr_devel("==>%s()\n", __func__);

	if (key->type != &key_type_asymmetric)
		return -EINVAL;
	subtype = asymmetric_key_subtype(key);
	if (!subtype ||
	    !key->payload.data)
		return -EINVAL;
	if (!subtype->verify_signature)
		return -ENOTSUPP;

	ret = subtype->verify_signature(key, sig);

	pr_devel("<==%s() = %d\n", __func__, ret);
	return ret;
}
EXPORT_SYMBOL_GPL(verify_signature);

/**
 * generate_signature - Initiate the use of an asymmetric key to generate a signature
 * @key: The asymmetric key to generate against
 * @M: The message to be signed, or a hash result. Dependent on the hash parameter
 * @hash_algo: The hash algorithm to generate digest
 * @hash: true means M is a original mesagse, false means M is a hash result
 *
 * Returns public_key-signature if successful or else an error.
 */
struct public_key_signature *generate_signature(const struct key *key, u8 *M,
		enum pkey_hash_algo hash_algo, const bool hash)
{
	const struct asymmetric_key_subtype *subtype;

	pr_info("==>%s()\n", __func__);

	if (key->type != &key_type_asymmetric)
		return ERR_PTR(-EINVAL);
	subtype = asymmetric_key_subtype(key);
	if (!subtype || !key->payload.data)
		return ERR_PTR(-EINVAL);
	if (!subtype->generate_signature)
		return ERR_PTR(-ENOTSUPP);

	return subtype->generate_signature(key, M, hash_algo, hash);
}
EXPORT_SYMBOL_GPL(generate_signature);

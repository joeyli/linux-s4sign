/* X.509 certificate parser
 *
 * Copyright (C) 2013 SUSE Linux Products GmbH. All rights reserved.
 * Written by Lee, Chun-Yi (jlee@suse.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#define pr_fmt(fmt) "PKCS8: "fmt
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <linux/oid_registry.h>
#include "public_key.h"
#include "pkcs8_parser.h"
#include "pkcs8-asn1.h"
#include "pkcs8_rsakey-asn1.h"

struct pkcs8_parse_context {
	struct pkcs8_info *info;		/* Certificate being constructed */
	unsigned long   data;			/* Start of data */
	const void      *key;                   /* Key data */
	size_t          key_size;               /* Size of key data */
	enum OID	algo_oid;		/* Algorithm OID */
	unsigned char   nr_mpi;		/* Number of MPIs stored */
};

/*
 * Free an PKCS #8 private key info
 */
void pkcs8_free_info(struct pkcs8_info *info)
{
	if (info) {
		public_key_destroy(info->priv);
		kfree(info);
	}
}

/*
 * Parse an PKCS #8 Private Key Info
 */
struct pkcs8_info *pkcs8_info_parse(const void *data, size_t datalen)
{
	struct pkcs8_info *info;
	struct pkcs8_parse_context *ctx;
	long ret;

	ret = -ENOMEM;
	info = kzalloc(sizeof(struct pkcs8_info), GFP_KERNEL);
	if (!info)
		goto error_no_info;
	info->priv = kzalloc(sizeof(struct private_key), GFP_KERNEL);
	if (!info->priv)
		goto error_no_ctx;
	ctx = kzalloc(sizeof(struct pkcs8_parse_context), GFP_KERNEL);
	if (!ctx)
		goto error_no_ctx;

	ctx->info = info;
	ctx->data = (unsigned long)data;

	/* Attempt to decode the private key info */
	ret = asn1_ber_decoder(&pkcs8_decoder, ctx, data, datalen);
	if (ret < 0)
		goto error_decode;

	/* Decode the private key */
	ret = asn1_ber_decoder(&pkcs8_rsakey_decoder, ctx,
			       ctx->key, ctx->key_size);
	if (ret < 0)
		goto error_decode;

	kfree(ctx);
	return info;

error_decode:
	kfree(ctx);
error_no_ctx:
	pkcs8_free_info(info);
error_no_info:
	return ERR_PTR(ret);
}

/*
 * Note an OID when we find one for later processing when we know how
 * to interpret it.
 */
int pkcs8_note_OID(void *context, size_t hdrlen,
	     unsigned char tag,
	     const void *value, size_t vlen)
{
	struct pkcs8_parse_context *ctx = context;

	ctx->algo_oid = look_up_OID(value, vlen);
	if (ctx->algo_oid == OID__NR) {
		char buffer[50];
		sprint_oid(value, vlen, buffer, sizeof(buffer));
		pr_debug("Unknown OID: [%lu] %s\n",
			 (unsigned long)value - ctx->data, buffer);
	}
	return 0;
}

/*
 * Extract the data for the private key algorithm
 */
int pkcs8_extract_key_data(void *context, size_t hdrlen,
		unsigned char tag,
		const void *value, size_t vlen)
{
	struct pkcs8_parse_context *ctx = context;

	if (ctx->algo_oid != OID_rsaEncryption)
		return -ENOPKG;

	ctx->info->pkey_algo = PKEY_ALGO_RSA;
	ctx->key = value;
	ctx->key_size = vlen;
	return 0;
}

/*
 * Extract a RSA private key value
 */
int rsa_priv_extract_mpi(void *context, size_t hdrlen,
		    unsigned char tag,
		    const void *value, size_t vlen)
{
	struct pkcs8_parse_context *ctx = context;
	MPI mpi;

	if (ctx->nr_mpi >= ARRAY_SIZE(ctx->info->priv->mpi)) {
		/* does not grab exponent1, exponent2 and coefficient */
		if (ctx->nr_mpi > 8) {
			pr_err("Too many public key MPIs in pkcs1 private key\n");
			return -EBADMSG;
		} else {
			ctx->nr_mpi++;
			return 0;
		}
	}

	mpi = mpi_read_raw_data(value, vlen);
	if (!mpi)
		return -ENOMEM;

	ctx->info->priv->mpi[ctx->nr_mpi++] = mpi;
	return 0;
}

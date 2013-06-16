/* RSA asymmetric public-key algorithm [RFC3447]
 *
 * Copyright (C) 2012 Red Hat, Inc. All Rights Reserved.
 * Written by David Howells (dhowells@redhat.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#define pr_fmt(fmt) "RSA: "fmt
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <crypto/hash.h>
#include "public_key.h"
#include "private_key.h"

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("RSA Public Key Algorithm");

#define kenter(FMT, ...) \
	pr_devel("==> %s("FMT")\n", __func__, ##__VA_ARGS__)
#define kleave(FMT, ...) \
	pr_devel("<== %s()"FMT"\n", __func__, ##__VA_ARGS__)

/*
 * Hash algorithm OIDs plus ASN.1 DER wrappings [RFC4880 sec 5.2.2].
 */
static const u8 RSA_digest_info_MD5[] = {
	0x30, 0x20, 0x30, 0x0C, 0x06, 0x08,
	0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x05, /* OID */
	0x05, 0x00, 0x04, 0x10
};

static const u8 RSA_digest_info_SHA1[] = {
	0x30, 0x21, 0x30, 0x09, 0x06, 0x05,
	0x2B, 0x0E, 0x03, 0x02, 0x1A,
	0x05, 0x00, 0x04, 0x14
};

static const u8 RSA_digest_info_RIPE_MD_160[] = {
	0x30, 0x21, 0x30, 0x09, 0x06, 0x05,
	0x2B, 0x24, 0x03, 0x02, 0x01,
	0x05, 0x00, 0x04, 0x14
};

static const u8 RSA_digest_info_SHA224[] = {
	0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09,
	0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04,
	0x05, 0x00, 0x04, 0x1C
};

static const u8 RSA_digest_info_SHA256[] = {
	0x30, 0x31, 0x30, 0x0d, 0x06, 0x09,
	0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
	0x05, 0x00, 0x04, 0x20
};

static const u8 RSA_digest_info_SHA384[] = {
	0x30, 0x41, 0x30, 0x0d, 0x06, 0x09,
	0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02,
	0x05, 0x00, 0x04, 0x30
};

static const u8 RSA_digest_info_SHA512[] = {
	0x30, 0x51, 0x30, 0x0d, 0x06, 0x09,
	0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03,
	0x05, 0x00, 0x04, 0x40
};

static const struct {
	const u8 *data;
	size_t size;
} RSA_ASN1_templates[PKEY_HASH__LAST] = {
#define _(X) { RSA_digest_info_##X, sizeof(RSA_digest_info_##X) }
	[PKEY_HASH_MD5]		= _(MD5),
	[PKEY_HASH_SHA1]	= _(SHA1),
	[PKEY_HASH_RIPE_MD_160]	= _(RIPE_MD_160),
	[PKEY_HASH_SHA256]	= _(SHA256),
	[PKEY_HASH_SHA384]	= _(SHA384),
	[PKEY_HASH_SHA512]	= _(SHA512),
	[PKEY_HASH_SHA224]	= _(SHA224),
#undef _
};

/*
 * RSAVP1() function [RFC3447 sec 5.2.2]
 */
static int RSAVP1(const struct public_key *key, MPI s, MPI *_m)
{
	MPI m;
	int ret;

	/* (1) Validate 0 <= s < n */
	if (mpi_cmp_ui(s, 0) < 0) {
		kleave(" = -EBADMSG [s < 0]");
		return -EBADMSG;
	}
	if (mpi_cmp(s, key->rsa.n) >= 0) {
		kleave(" = -EBADMSG [s >= n]");
		return -EBADMSG;
	}

	m = mpi_alloc(0);
	if (!m)
		return -ENOMEM;

	/* (2) m = s^e mod n */
	ret = mpi_powm(m, s, key->rsa.e, key->rsa.n);
	if (ret < 0) {
		mpi_free(m);
		return ret;
	}

	*_m = m;
	return 0;
}

/*
 * Integer to Octet String conversion [RFC3447 sec 4.1]
 */
static int _RSA_I2OSP(MPI x, unsigned *X_size, u8 **_X)
{
	int X_sign;
	u8 *X;

	X = mpi_get_buffer(x, X_size, &X_sign);
	if (!X)
		return -ENOMEM;
	if (X_sign < 0) {
		kfree(X);
		return -EBADMSG;
	}

	*_X = X;
	return 0;
}

static int RSA_I2OSP(MPI x, size_t xLen, u8 **_X)
{
	unsigned x_size;
	unsigned X_size;
	u8 *X = NULL;
	int ret;

	/* Make sure the string is the right length.  The number should begin
	 * with { 0x00, 0x01, ... } so we have to account for 15 leading zero
	 * bits not being reported by MPI.
	 */
	x_size = mpi_get_nbits(x);
	pr_devel("size(x)=%u xLen*8=%zu\n", x_size, xLen * 8);
	if (x_size != xLen * 8 - 15)
		return -ERANGE;

	ret = _RSA_I2OSP(x, &X_size, &X);
	if (ret < 0)
		return ret;

	if (X_size != xLen - 1) {
		kfree(X);
		return -EBADMSG;
	}

	*_X = X;
	return 0;
}

/*
 * Octet String to Integer conversion [RFC3447 sec 4.2]
 */
static int RSA_OS2IP(u8 *X, size_t XLen, MPI *_x)
{
	MPI x;

	x = mpi_alloc((XLen + BYTES_PER_MPI_LIMB - 1) / BYTES_PER_MPI_LIMB);
	mpi_set_buffer(x, X, XLen, 0);

	*_x = x;
	return 0;
}

/*
 * EMSA_PKCS1-v1_5-ENCODE [RFC3447 sec 9.2]
 * @M: message to be signed, an octet string
 * @emLen: intended length in octets of the encoded message
 * @hash_algo: hash function (option)
 * @hash: true means hash M, otherwise M is already a digest
 * @EM: encoded message, an octet string of length emLen
 *
 * This function is a implementation of the EMSA-PKCS1-v1_5 encoding operation
 * in RSA PKCS#1 spec. It used by the signautre generation operation of
 * RSASSA-PKCS1-v1_5 to encode message M to encoded message EM.
 *
 * The variables used in this function accord PKCS#1 spec but not follow kernel
 * naming convention, it useful when look at them with spec.
 */
static int EMSA_PKCS1_v1_5_ENCODE(const u8 *M, size_t emLen,
		enum pkey_hash_algo hash_algo, const bool hash,
		u8 **EM, struct public_key_signature *pks)
{
	u8 *digest;
	struct crypto_shash *tfm;
	struct shash_desc *desc;
	size_t digest_size, desc_size;
	size_t tLen;
	u8 *T, *PS, *EM_tmp;
	int i, ret;

	pr_info("EMSA_PKCS1_v1_5_ENCODE start\n");

	if (!RSA_ASN1_templates[hash_algo].data)
		ret = -ENOTSUPP;
	else
		pks->pkey_hash_algo = hash_algo;

	/* 1) Apply the hash function to the message M to produce a hash value H */
	tfm = crypto_alloc_shash(pkey_hash_algo[hash_algo], 0, 0);
	if (IS_ERR(tfm))
		return (PTR_ERR(tfm) == -ENOENT) ? -ENOPKG : PTR_ERR(tfm);

	desc_size = crypto_shash_descsize(tfm) + sizeof(*desc);
	digest_size = crypto_shash_digestsize(tfm);

	ret = -ENOMEM;

	digest = kzalloc(digest_size + desc_size, GFP_KERNEL);
	if (!digest)
		goto error_digest;
	pks->digest = digest;
	pks->digest_size = digest_size;

	if (hash) {
		desc = (void *) digest + digest_size;
		desc->tfm = tfm;
		desc->flags = CRYPTO_TFM_REQ_MAY_SLEEP;

		ret = crypto_shash_init(desc);
		if (ret < 0)
			goto error_shash;
		ret = crypto_shash_finup(desc, M, sizeof(M), pks->digest);
		if (ret < 0)
			goto error_shash;
	} else {
		memcpy(pks->digest, M, pks->digest_size);
		pks->digest_size = digest_size;
	}
	crypto_free_shash(tfm);

	/* 2) Encode the algorithm ID for the hash function and the hash value into
	 * an ASN.1 value of type DigestInfo with the DER. Let T be the DER encoding of
	 * the DigestInfo value and let tLen be the length in octets of T.
	 */
	tLen = RSA_ASN1_templates[hash_algo].size + pks->digest_size;
	T = kmalloc(tLen, GFP_KERNEL);
	if (!T)
		goto error_T;

	memcpy(T, RSA_ASN1_templates[hash_algo].data, RSA_ASN1_templates[hash_algo].size);
	memcpy(T + RSA_ASN1_templates[hash_algo].size, pks->digest, pks->digest_size);

	/* 3) check If emLen < tLen + 11, output "intended encoded message length too short" */
	if (emLen < tLen + 11) {
		ret = -EINVAL;
		goto error_emLen;
	}

	/* 4) Generate an octet string PS consisting of emLen - tLen - 3 octets with 0xff. */
	PS = kmalloc(emLen - tLen - 3, GFP_KERNEL);
	if (!PS)
		goto error_P;

	for (i = 0; i < (emLen - tLen - 3); i++)
		PS[i] = 0xff;

	/* 5) Concatenate PS, the DER encoding T, and other padding to form the encoded
	 * message EM as EM = 0x00 || 0x01 || PS || 0x00 || T
	 */
	EM_tmp = kmalloc(3 + emLen - tLen - 3 + tLen, GFP_KERNEL);
	if (!EM_tmp)
		goto error_EM;

	EM_tmp[0] = 0x00;
	EM_tmp[1] = 0x01;
	memcpy(EM_tmp + 2, PS, emLen - tLen - 3);
	EM_tmp[2 + emLen - tLen - 3] = 0x00;
	memcpy(EM_tmp + 2 + emLen - tLen - 3 + 1, T, tLen);

	*EM = EM_tmp;

	kfree(PS);
	kfree(T);

	return 0;

error_EM:
	kfree(PS);
error_P:
error_emLen:
	kfree(T);
error_T:
error_shash:
	kfree(digest);
error_digest:
	crypto_free_shash(tfm);
	return ret;
}

/*
 * Perform the RSA signature verification.
 * @H: Value of hash of data and metadata
 * @EM: The computed signature value
 * @k: The size of EM (EM[0] is an invalid location but should hold 0x00)
 * @hash_size: The size of H
 * @asn1_template: The DigestInfo ASN.1 template
 * @asn1_size: Size of asm1_template[]
 */
static int RSA_verify(const u8 *H, const u8 *EM, size_t k, size_t hash_size,
		      const u8 *asn1_template, size_t asn1_size)
{
	unsigned PS_end, T_offset, i;

	kenter(",,%zu,%zu,%zu", k, hash_size, asn1_size);

	if (k < 2 + 1 + asn1_size + hash_size)
		return -EBADMSG;

	/* Decode the EMSA-PKCS1-v1_5 */
	if (EM[1] != 0x01) {
		kleave(" = -EBADMSG [EM[1] == %02u]", EM[1]);
		return -EBADMSG;
	}

	T_offset = k - (asn1_size + hash_size);
	PS_end = T_offset - 1;
	if (EM[PS_end] != 0x00) {
		kleave(" = -EBADMSG [EM[T-1] == %02u]", EM[PS_end]);
		return -EBADMSG;
	}

	for (i = 2; i < PS_end; i++) {
		if (EM[i] != 0xff) {
			kleave(" = -EBADMSG [EM[PS%x] == %02u]", i - 2, EM[i]);
			return -EBADMSG;
		}
	}

	if (memcmp(asn1_template, EM + T_offset, asn1_size) != 0) {
		kleave(" = -EBADMSG [EM[T] ASN.1 mismatch]");
		return -EBADMSG;
	}

	if (memcmp(H, EM + T_offset + asn1_size, hash_size) != 0) {
		kleave(" = -EKEYREJECTED [EM[T] hash mismatch]");
		return -EKEYREJECTED;
	}

	kleave(" = 0");
	return 0;
}

/*
 * Perform the verification step [RFC3447 sec 8.2.2].
 */
static int RSA_verify_signature(const struct public_key *key,
				const struct public_key_signature *sig)
{
	size_t tsize;
	int ret;

	/* Variables as per RFC3447 sec 8.2.2 */
	const u8 *H = sig->digest;
	u8 *EM = NULL;
	MPI m = NULL;
	size_t k;

	kenter("");

	if (!RSA_ASN1_templates[sig->pkey_hash_algo].data)
		return -ENOTSUPP;

	/* (1) Check the signature size against the public key modulus size */
	k = mpi_get_nbits(key->rsa.n);
	tsize = mpi_get_nbits(sig->rsa.s);

	/* According to RFC 4880 sec 3.2, length of MPI is computed starting
	 * from most significant bit.  So the RFC 3447 sec 8.2.2 size check
	 * must be relaxed to conform with shorter signatures - so we fail here
	 * only if signature length is longer than modulus size.
	 */
	pr_devel("step 1: k=%zu size(S)=%zu\n", k, tsize);
	if (k < tsize) {
		ret = -EBADMSG;
		goto error;
	}

	/* Round up and convert to octets */
	k = (k + 7) / 8;

	/* (2b) Apply the RSAVP1 verification primitive to the public key */
	ret = RSAVP1(key, sig->rsa.s, &m);
	if (ret < 0)
		goto error;

	/* (2c) Convert the message representative (m) to an encoded message
	 *      (EM) of length k octets.
	 *
	 *      NOTE!  The leading zero byte is suppressed by MPI, so we pass a
	 *      pointer to the _preceding_ byte to RSA_verify()!
	 */
	ret = RSA_I2OSP(m, k, &EM);
	if (ret < 0)
		goto error;

	ret = RSA_verify(H, EM - 1, k, sig->digest_size,
			 RSA_ASN1_templates[sig->pkey_hash_algo].data,
			 RSA_ASN1_templates[sig->pkey_hash_algo].size);

error:
	kfree(EM);
	mpi_free(m);
	kleave(" = %d", ret);
	return ret;
}

/*
 * Perform the generation step [RFC3447 sec 8.2.1].
 */
static struct public_key_signature *RSA_generate_signature(
		const struct private_key *key, u8 *M,
		enum pkey_hash_algo hash_algo, const bool hash)
{
	struct public_key_signature *pks;
	u8 *EM = NULL;
	MPI m = NULL;
	MPI s = NULL;
	unsigned X_size;
	size_t emLen;
	int ret;

	pr_info("RSA_generate_signature start\n");

	ret = -ENOMEM;
	pks = kzalloc(sizeof(*pks), GFP_KERNEL);
	if (!pks)
		goto error_no_pks;

	/* 1): EMSA-PKCS1-v1_5 encoding: */
	/* Use the private key modulus size to be EM length */
	emLen = mpi_get_nbits(key->rsa.n);
	emLen = (emLen + 7) / 8;

	ret = EMSA_PKCS1_v1_5_ENCODE(M, emLen, hash_algo, hash, &EM, pks);
	if (ret < 0)
		goto error_v1_5_encode;

	/* 2): m = OS2IP (EM) */
	ret = RSA_OS2IP(EM, emLen, &m);
	if (ret < 0)
		goto error_v1_5_encode;

	/* TODO 3): s = RSASP1 (K, m) */
	s = m;

	/* 4): S = I2OSP (s, k) */
	_RSA_I2OSP(s, &X_size, &pks->S);

	return pks;

error_v1_5_encode:
	kfree(pks);
error_no_pks:
	pr_info("<==%s() = %d\n", __func__, ret);
	return ERR_PTR(ret);
}

const struct public_key_algorithm RSA_public_key_algorithm = {
	.name		= "RSA",
	.n_pub_mpi	= 2,
	.n_sec_mpi	= 3,
	.n_sig_mpi	= 1,
	.verify_signature = RSA_verify_signature,
};
EXPORT_SYMBOL_GPL(RSA_public_key_algorithm);

const struct private_key_algorithm RSA_private_key_algorithm = {
	.name           = "RSA",
	.n_pub_mpi      = 2,
	.n_sec_mpi      = 3,
	.n_sig_mpi      = 1,
	.generate_signature = RSA_generate_signature,
};
EXPORT_SYMBOL_GPL(RSA_private_key_algorithm);

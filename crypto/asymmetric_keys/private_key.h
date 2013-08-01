/* Private key algorithm internals
 *
 * Copyright (C) 2013 SUSE Linux Products GmbH. All rights reserved.
 * Written by Chun-Yi Lee (jlee@suse.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#include <crypto/public_key.h>

extern struct asymmetric_key_subtype private_key_subtype;

/*
 * Private key algorithm definition.
 */
struct private_key_algorithm {
	const char	*name;
	u8		n_pub_mpi;	/* Number of MPIs in public key */
	u8		n_sec_mpi;	/* Number of MPIs in secret key */
	u8		n_sig_mpi;	/* Number of MPIs in a signature */
	struct public_key_signature* (*generate_signature)(
		const struct private_key *key, u8 *M,
		enum pkey_hash_algo hash_algo, const bool hash);
};

extern const struct private_key_algorithm RSA_private_key_algorithm;

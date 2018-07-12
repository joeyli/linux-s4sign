/* efi-type.h: EFI key type
 *
 * Copyright (C) 2018 Lee, Chun-Yi <jlee@suse.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#ifndef _KEYS_EFI_TYPE_H
#define _KEYS_EFI_TYPE_H

#include <linux/key.h>
#include <linux/rcupdate.h>

#define MIN_KEY_SIZE			32
#define MAX_KEY_SIZE			128
#define MAX_BLOB_SIZE			512			//TODO: set a max size ??

struct efi_key_payload {
	struct rcu_head rcu;
	u8 *key;
	u8 *datablob;			/* key_len(string) + ERK hash + iv + encrypted key */
	char *key_len_str;
	u8 *erk_hash;
	u8 *iv;
	u8 *encrypted_key;
	u8 *hmac;
	unsigned int key_len;
	unsigned int datablob_len;
	u8 payload_data[0];		/* key + datablob + hmac */
};

extern struct key_type key_type_efi;

extern long efi_read_blob(const struct key *key, char __user *buffer,
			  char *kbuffer, size_t buflen);

#endif /* _KEYS_EFI_TYPE_H */

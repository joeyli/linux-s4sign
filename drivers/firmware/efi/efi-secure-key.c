/* EFI secure key
 *
 * Copyright (C) 2018 Lee, Chun-Yi <jlee@suse.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#include <linux/efi.h>
#include <linux/memblock.h>
#include <linux/security.h>

static u8 root_key[ROOT_KEY_SIZE];
static unsigned long rkey_size;
static bool is_loaded;
static bool is_secure;

static void __init
print_efi_rkey_setup_data(struct efi_rkey_setup_data *rkey_setup)
{
	pr_debug("EFI root key detection status: %s 0x%lx\n",
		efi_status_to_str(rkey_setup->detect_status),
		rkey_setup->detect_status);
	pr_debug("EFI root key getting status: %s 0x%lx\n",
		efi_status_to_str(rkey_setup->final_status),
		rkey_setup->final_status);
	pr_debug("EFI root key size: %ld\n", rkey_setup->key_size);

	if (rkey_setup->final_status != EFI_SUCCESS) {
		pr_warn("EFI root key getting failed: %s 0x%lx\n",
			efi_status_to_str(rkey_setup->final_status),
			rkey_setup->final_status);
	} else if (rkey_setup->key_size < ROOT_KEY_SIZE) {
		pr_warn(KERN_CONT "EFI root key size %ld is less than %d.\n",
			rkey_setup->key_size, ROOT_KEY_SIZE);
	}
}

void __init parse_efi_root_key_setup(u64 phys_addr, u32 data_len)
{
	struct efi_rkey_setup_data *rkey_setup;
	void *setup_data;

	setup_data = early_memremap(phys_addr, data_len);
	rkey_setup = setup_data + sizeof(struct setup_data);
	print_efi_rkey_setup_data(rkey_setup);

	/* keep efi root key */
	if (rkey_setup->final_status == EFI_SUCCESS) {
		memcpy(root_key, rkey_setup->root_key, rkey_setup->key_size);
		rkey_size = rkey_setup->key_size;
		is_loaded = true;
		is_secure = rkey_setup->is_secure;
		pr_info("EFI root key is loaded.\n");
		if (!is_secure) {
			pr_warn("EFI root key is insecure when no secure boot.\n");
		}
	}

	/* erase setup data */
	memzero_explicit(setup_data,
		sizeof(struct setup_data) + sizeof(struct efi_rkey_setup_data));
	early_iounmap(setup_data, data_len);
}

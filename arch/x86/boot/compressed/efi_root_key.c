/* EFI root key generator
 *
 * Copyright (C) 2018 Lee, Chun-Yi <jlee@suse.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#include <linux/efi.h>
#include <asm/efi.h>

#include "misc.h"

static efi_system_table_t *s_table;
static struct boot_params *b_params;

#ifdef DEBUG
#define debug_putstr(__x)  efi_printk(s_table, (char *)__x)
#else
#define debug_putstr(__x)
#endif

static void efi_printk_status(char *reason, efi_status_t status)
{
	efi_printk(s_table, reason);
	efi_printk(s_table, efi_status_to_str(status));
	efi_printk(s_table, "\n");
}

static unsigned long get_boot_seed(void)
{
	unsigned long hash = 0;

	hash = rotate_xor(hash, build_str, sizeof(build_str));
	hash = rotate_xor(hash, b_params, sizeof(*b_params));

	return hash;
}

#include "../../lib/random.c"

static void generate_root_key(u8 key[], unsigned int size)
{
	unsigned int bfill = size;

	if (key == NULL || !size)
		return;

	memset(key, 0, size);
	while (bfill > 0) {
		unsigned long entropy = 0;
		unsigned int copy_len = 0;
		entropy = get_random_long("EFI root key");
		copy_len = (bfill < sizeof(entropy)) ? bfill : sizeof(entropy);
		memcpy((void *)(key + size - bfill), &entropy, copy_len);
		bfill -= copy_len;
	}
}

#define get_efi_var(name, vendor, ...) \
	efi_call_runtime(get_variable, \
			(efi_char16_t *)(name), (efi_guid_t *)(vendor), \
			__VA_ARGS__);
#define set_efi_var(name, vendor, ...) \
	efi_call_runtime(set_variable, \
			(efi_char16_t *)(name), (efi_guid_t *)(vendor), \
			__VA_ARGS__);

static efi_char16_t const root_key_name[] = {
	'R', 'o', 'o', 't', 'K', 'e', 'y', 0
};
#define ROOT_KEY_ATTRIBUTE	(EFI_VARIABLE_NON_VOLATILE | \
				EFI_VARIABLE_BOOTSERVICE_ACCESS)

static efi_status_t get_root_key(unsigned long *attributes,
			unsigned long *key_size,
			struct efi_rkey_setup_data *rkey_setup)
{
	void *key_data;
	efi_status_t status;

	status = efi_call_early(allocate_pool, EFI_LOADER_DATA,
				*key_size, &key_data);
	if (status != EFI_SUCCESS) {
		efi_printk_status("Failed to allocate mem: \n", status);
		return status;
	}
	memset(key_data, 0, *key_size);
	status = get_efi_var(root_key_name, &EFI_SECURE_GUID,
			     attributes, key_size, key_data);
	if (status != EFI_SUCCESS) {
		efi_printk_status("Failed to get root key: ", status);
		goto err;
	}

	memset(rkey_setup->root_key, 0, ROOT_KEY_SIZE);
	memcpy(rkey_setup->root_key, key_data,
	       (*key_size >= ROOT_KEY_SIZE) ? ROOT_KEY_SIZE : *key_size);
err:
	efi_call_early(free_pool, key_data);
	return status;
}

static efi_status_t remove_root_key(unsigned long attributes)
{
	efi_status_t status;

	status = set_efi_var(root_key_name,
			     &EFI_SECURE_GUID, attributes, 0, NULL);
	if (status == EFI_SUCCESS)
		efi_printk(s_table, "Removed root key\n");
	else
		efi_printk_status("Failed to remove root key: ", status);

	return status;
}

static efi_status_t create_root_key(struct efi_rkey_setup_data *rkey_setup)
{
	efi_status_t status;

	efi_printk(s_table, "Create new root key\n");
	generate_root_key(rkey_setup->root_key, ROOT_KEY_SIZE);
	status = set_efi_var(root_key_name, &EFI_SECURE_GUID,
			     ROOT_KEY_ATTRIBUTE, ROOT_KEY_SIZE,
			     rkey_setup->root_key);
	if (status != EFI_SUCCESS)
		efi_printk_status("Failed to write root key: ", status);

	return status;
}

static efi_status_t regen_root_key(struct efi_rkey_setup_data *rkey_setup)
{
	unsigned long attributes = 0;
	unsigned long key_size = ROOT_KEY_SIZE;
	efi_status_t status;

	status = remove_root_key(attributes);
	if (status == EFI_SUCCESS)
		status = create_root_key(rkey_setup);
	if (status == EFI_SUCCESS)
		status = get_root_key(&attributes, &key_size, rkey_setup);
}

void efi_setup_root_key(efi_system_table_t *sys_table, struct boot_params *params)
{
	struct setup_data *setup_data, *rkey_setup_data;
	unsigned long setup_size = 0;
	unsigned long attributes = 0;
	unsigned long key_size = 0;
	struct efi_rkey_setup_data *rkey_setup;
	efi_status_t status;

	s_table = sys_table;
	b_params = params;

	setup_size = sizeof(struct setup_data) + sizeof(struct efi_rkey_setup_data);
	status = efi_call_early(allocate_pool, EFI_LOADER_DATA,
				setup_size, &rkey_setup_data);
	if (status != EFI_SUCCESS) {
		efi_printk(s_table, "Failed to allocate mem for root key\n");
		return;
	}
	memset(rkey_setup_data, 0, setup_size);
	rkey_setup = (struct efi_rkey_setup_data *) rkey_setup_data->data;

	/* detect the size of root key variable */
	status = get_efi_var(root_key_name, &EFI_SECURE_GUID,
			     &attributes, &key_size, NULL);
	rkey_setup->detect_status = status;
	switch (status) {
	case EFI_BUFFER_TOO_SMALL:
		status = get_root_key(&attributes, &key_size, rkey_setup);
		if (status != EFI_SUCCESS)
			break;
		if (attributes != ROOT_KEY_ATTRIBUTE) {
			efi_printk(sys_table, "Found a unqualified root key\n");
			status = regen_root_key(rkey_setup);
		}
		break;

	case EFI_NOT_FOUND:
		status = create_root_key(rkey_setup);
		if (status == EFI_SUCCESS) {
			key_size = ROOT_KEY_SIZE;
			status = get_root_key(&attributes, &key_size, rkey_setup);
		}
		break;

	default:
		efi_printk_status("Failed to detect root key's size: ", status);
	}

	rkey_setup->is_secure =
		efi_get_secureboot(sys_table) == efi_secureboot_mode_enabled;
	rkey_setup->key_size = key_size;
	rkey_setup->final_status = status;

	rkey_setup_data->type = SETUP_EFI_ROOT_KEY;
	rkey_setup_data->len = sizeof(struct efi_rkey_setup_data);
	rkey_setup_data->next = 0;
	setup_data = (struct setup_data *)params->hdr.setup_data;
	while (setup_data && setup_data->next)
		setup_data = (struct setup_data *)setup_data->next;
	if (setup_data)
		setup_data->next = (unsigned long)rkey_setup_data;
	else
		params->hdr.setup_data = (unsigned long)rkey_setup_data;
}

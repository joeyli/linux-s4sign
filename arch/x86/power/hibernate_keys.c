/* Swsusp keys handler
 *
 * Copyright (C) 2015 SUSE Linux Products GmbH. All rights reserved.
 * Written by Chun-Yi Lee (jlee@suse.com)
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public Licence
 * as published by the Free Software Foundation; either version
 * 2 of the Licence, or (at your option) any later version.
 */

#include <linux/bootmem.h>
#include <linux/memblock.h>
#include <linux/suspend.h>
#include <asm/suspend.h>

/* physical address of swsusp keys from boot params */
static u64 keys_phys_addr;

/* A page used to keep swsusp keys */
static struct swsusp_keys *swsusp_keys;

void __init parse_swsusp_keys(u64 phys_addr, u32 data_len)
{
	struct setup_data *swsusp_setup_data;

	/* Reserve keys memory, will copy and earse in init_hibernate_keys() */
	keys_phys_addr = phys_addr + sizeof(struct setup_data);
	memblock_reserve(keys_phys_addr, sizeof(struct swsusp_keys));

	/* clear setup_data */
	swsusp_setup_data = early_memremap(phys_addr, data_len);
	if (!swsusp_setup_data)
		return;

	memset(swsusp_setup_data, 0, sizeof(struct setup_data));
	early_memunmap(swsusp_setup_data, data_len);
}

int get_swsusp_key(u8 **skey)
{
	if (!swsusp_keys)
		return -ENODEV;

	if (!swsusp_keys->skey_status)
		*skey = swsusp_keys->swsusp_key;

	return swsusp_keys->skey_status;
}

bool swsusp_page_is_keys(struct page *page)
{
	bool ret = false;

	if (!swsusp_keys || swsusp_keys->skey_status)
		return ret;

	ret = (page_to_pfn(page) == page_to_pfn(virt_to_page(swsusp_keys)));
	if (ret)
		pr_info("PM: Avoid snapshot the page of swsusp key.\n");

	return ret;
}

static int __init init_hibernate_keys(void)
{
	struct swsusp_keys *keys;
	int ret = 0;

	if (!keys_phys_addr)
		return -ENODEV;

	keys = early_memremap(keys_phys_addr, sizeof(struct swsusp_keys));

	/* Copy swsusp keys to a allocated page */
	swsusp_keys = (struct swsusp_keys *)get_zeroed_page(GFP_KERNEL);
	if (swsusp_keys) {
		*swsusp_keys = *keys;
	} else {
		pr_err("PM: Allocate swsusp keys page failed\n");
		ret = -ENOMEM;
	}

	/* Earse keys data no matter copy success or failed */
	memset(keys, 0, sizeof(struct swsusp_keys));
	early_memunmap(keys, sizeof(struct swsusp_keys));
	memblock_free(keys_phys_addr, sizeof(struct swsusp_keys));
	keys_phys_addr = 0;

	return ret;
}

late_initcall(init_hibernate_keys);

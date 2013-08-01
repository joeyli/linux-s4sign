#include <linux/sched.h>
#include <linux/efi.h>
#include <linux/mpi.h>
#include <crypto/public_key.h>
#include <keys/asymmetric-type.h>

#include "power.h"

#define EFI_HIBERNATE_GUID \
	EFI_GUID(0xfe141863, 0xc070, 0x478e, 0xb8, 0xa3, 0x87, 0x8a, 0x5d, 0xc9, 0xef, 0x21)
static efi_char16_t efi_s4_sign_key_name[10] = { 'S', '4', 'S', 'i', 'g', 'n', 'K', 'e', 'y', 0 };
static efi_char16_t efi_s4_wake_key_name[10] = { 'S', '4', 'W', 'a', 'k', 'e', 'K', 'e', 'y', 0 };

static void *skey_page_addr;
static unsigned long skey_dsize;

static int efi_status_to_err(efi_status_t status)
{
	int err;

	switch (status) {
	case EFI_INVALID_PARAMETER:
		err = -EINVAL;
		break;
	case EFI_OUT_OF_RESOURCES:
		err = -ENOSPC;
		break;
	case EFI_DEVICE_ERROR:
		err = -EIO;
		break;
	case EFI_WRITE_PROTECTED:
		err = -EROFS;
		break;
	case EFI_SECURITY_VIOLATION:
		err = -EACCES;
		break;
	case EFI_NOT_FOUND:
		err = -EIO;
		break;
	default:
		err = -EINVAL;
	}

	return err;
}

bool swsusp_page_is_sign_key(struct page *page)
{
	unsigned long skey_page_addr_pfn;
	bool ret;

	if (!skey_page_addr || IS_ERR(skey_page_addr))
		return false;

	skey_page_addr_pfn = page_to_pfn(virt_to_page(skey_page_addr));
	ret = (page_to_pfn(page) == skey_page_addr_pfn) ? true : false;
	if (ret)
		pr_info("PM: Avoid snapshot the page of S4 sign key.\n");

	return ret;
}

static void *efi_key_load_data(efi_char16_t *var_name, unsigned long *datasize,
				bool clean)
{
	u32 attributes;
	void *data_page;
	efi_status_t status;

	if (!efi_enabled(EFI_RUNTIME_SERVICES))
		return ERR_PTR(-EPERM);

	/* obtain the size */
	*datasize = 0;
	status = efi.get_variable(var_name, &EFI_HIBERNATE_GUID,
				  NULL, datasize, NULL);
	if (status != EFI_BUFFER_TOO_SMALL) {
		data_page = ERR_PTR(efi_status_to_err(status));
		pr_err("PM: Couldn't get key data size: 0x%lx\n", status);
		goto error_size;
	}
	if (*datasize > PAGE_SIZE) {
		data_page = ERR_PTR(-EBADMSG);
		goto error_size;
	}

	data_page = (void *)get_zeroed_page(GFP_KERNEL);
	if (!data_page) {
		data_page = ERR_PTR(-ENOMEM);
		goto error_page;
	}
	status = efi.get_variable(var_name, &EFI_HIBERNATE_GUID,
				&attributes, datasize, data_page);
	if (status) {
		data_page = ERR_PTR(efi_status_to_err(status));
		pr_err("PM: Get key data error: %ld\n", PTR_ERR(data_page));
		goto error_get;
	}

	if (!clean)
		goto no_clean;

	/* clean S4 key data from EFI variable */
	status = efi.set_variable(var_name, &EFI_HIBERNATE_GUID, attributes, 0, NULL);
	if (status != EFI_SUCCESS)
		pr_warn("PM: Clean key data error: %lx, %d\n", status, efi_status_to_err(status));
	else
		pr_info("PM: Clean key data success!");

no_clean:
	return data_page;

error_get:
	free_page((unsigned long) data_page);
	*datasize = 0;
error_page:
error_size:
	return data_page;
}

int load_sign_key_data(void)
{
	void *page_addr;
	unsigned long data_size;
	int ret = 0;

	data_size = 0;
	page_addr = efi_key_load_data(efi_s4_sign_key_name, &data_size, true);
	if (IS_ERR(page_addr)) {
		ret = PTR_ERR(page_addr);
		pr_err("PM: Load s4 sign key data error: %d\n", ret);
	} else {
		if (skey_page_addr && !IS_ERR(skey_page_addr)) {
			memset(skey_page_addr, 0, skey_dsize);
			free_page((unsigned long) skey_page_addr);
		}
		skey_dsize = data_size;
		skey_page_addr = page_addr;
		pr_info("PM: Load s4 sign key data success!\n");
	}

	return ret;
}

bool sign_key_data_loaded(void)
{
	return skey_page_addr && !IS_ERR(skey_page_addr);
}

struct key *get_sign_key(void)
{
	const struct cred *cred = current_cred();
	struct key *skey;
	int err;

	if (!skey_page_addr || IS_ERR(skey_page_addr))
		return ERR_PTR(-EBADMSG);

	skey = key_alloc(&key_type_asymmetric, "s4_sign_key",
			GLOBAL_ROOT_UID, GLOBAL_ROOT_GID,
			cred, 0, KEY_ALLOC_NOT_IN_QUOTA);
	if (IS_ERR(skey)) {
		pr_err("PM: Allocate s4 sign key error: %ld\n", PTR_ERR(skey));
		goto error_keyalloc;
	}
	err = key_instantiate_and_link(skey, skey_page_addr, skey_dsize, NULL, NULL);
	if (err < 0) {
		pr_err("PM: S4 sign key instantiate error: %d\n", err);
		if (skey)
			key_put(skey);
		skey = ERR_PTR(err);
		goto error_keyinit;
	}

	return skey;

error_keyinit:
	free_page((unsigned long)skey_page_addr);
	skey_dsize = 0;
error_keyalloc:
	return skey;
}

void destroy_sign_key(struct key *skey)
{
	if (!skey_page_addr || IS_ERR(skey_page_addr))
		return;

	memset(skey_page_addr, 0, skey_dsize);
	free_page((unsigned long)skey_page_addr);
	skey_dsize = 0;
	if (skey)
		key_put(skey);
}

int find_wake_key_data(void)
{
	unsigned long datasize = 0;
	efi_status_t status;
	int ret = 0;

	if (!efi_enabled(EFI_RUNTIME_SERVICES))
		return -EPERM;

	/* obtain the size */
	status = efi.get_variable(efi_s4_wake_key_name, &EFI_HIBERNATE_GUID,
				  NULL, &datasize, NULL);
	if (status != EFI_BUFFER_TOO_SMALL) {
		ret = efi_status_to_err(status);
		pr_err("PM: Couldn't find key data size: 0x%lx\n", status);
	}

	return ret;
}

struct key *load_wake_key(void)
{
	const struct cred *cred = current_cred();
	void *page_addr;
	unsigned long datasize = 0;
	struct key *wkey;
	int err;

	page_addr = efi_key_load_data(efi_s4_wake_key_name, &datasize, false);
	if (IS_ERR(page_addr)) {
		wkey = (struct key *)page_addr;
		goto error_data;
	}

	wkey = key_alloc(&key_type_asymmetric, "s4_wake_key",
			GLOBAL_ROOT_UID, GLOBAL_ROOT_GID,
			cred, 0, KEY_ALLOC_NOT_IN_QUOTA);
	if (IS_ERR(wkey)) {
		pr_err("PM: Allocate s4 wake key error: %ld\n", PTR_ERR(wkey));
		goto error_keyalloc;
	}
	err = key_instantiate_and_link(wkey, page_addr, datasize, NULL, NULL);
	if (err < 0) {
		pr_err("PM: S4 wake key instantiate error: %d\n", err);
		if (wkey)
			key_put(wkey);
		wkey = ERR_PTR(err);
	}

error_keyalloc:
	free_page((unsigned long)page_addr);
error_data:
	return wkey;
}

size_t get_key_length(const struct key *key)
{
	const struct public_key *pk = key->payload.data;
	size_t len;

	/* TODO: better check the RSA type */

	len = mpi_get_nbits(pk->rsa.n);
	len = (len + 7) / 8;

	return len;
}

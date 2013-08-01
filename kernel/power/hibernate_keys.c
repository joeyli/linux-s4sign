#include <linux/sched.h>
#include <linux/efi.h>
#include <linux/mpi.h>
#include <linux/asn1.h>
#include <crypto/public_key.h>
#include <keys/asymmetric-type.h>

#include "power.h"

static void *skey_data;
static void *skey_data_buf;
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
		err = -ENODATA;
		break;
	default:
		err = -EINVAL;
	}

	return err;
}

bool swsusp_page_is_sign_key(struct page *page)
{
	unsigned long skey_data_pfn;
	bool ret;

	if (!skey_data || IS_ERR(skey_data))
		return false;

	skey_data_pfn = page_to_pfn(virt_to_page(skey_data));
	ret = (page_to_pfn(page) == skey_data_pfn) ? true : false;
	if (ret)
		pr_info("PM: Avoid snapshot the page of S4 sign key.\n");

	return ret;
}

unsigned long get_skey_data_buf_pfn(void)
{
	if (!skey_data_buf || IS_ERR(skey_data_buf))
		return 0;

	return page_to_pfn(virt_to_page(skey_data_buf));
}

void clone_skey_data(void *page)
{
	if (!page)
		return;

	if (skey_data && !IS_ERR(skey_data)) {
		memcpy(page, &skey_dsize, sizeof(skey_dsize));
		memcpy(page + sizeof(skey_dsize), skey_data, PAGE_SIZE - sizeof(skey_dsize));
	}
}

void restore_sign_key_data(void)
{
	memset(skey_data, 0, PAGE_SIZE);
	if (skey_data_buf && !IS_ERR(skey_data_buf)) {
		/* restore sign key size and data from buffer */
		memcpy(&skey_dsize, skey_data_buf, sizeof(skey_dsize));
		memcpy(skey_data, skey_data_buf + sizeof(skey_dsize),
				PAGE_SIZE - sizeof(skey_dsize));
		/* reset skey page buffer */
		memset(skey_data_buf, 0, PAGE_SIZE);
		pr_info("PM: Restore S4 sign key from buffer\n");
	} else
		pr_err("PM: Restore S4 sign key fail\n");
}

bool skey_data_available(void)
{
	static unsigned char const_seq = (ASN1_SEQ | (ASN1_CONS << 5));
	bool ret = false;

	/* Sign key is PKCS#8 format that must be a Constructed SEQUENCE */
	ret = skey_data && !IS_ERR(skey_data) &&
		(skey_dsize != 0) &&
		((unsigned char *)skey_data)[0] == const_seq;

	return ret;
}

struct key *get_sign_key(void)
{
	const struct cred *cred = current_cred();
	struct key *skey;
	int err;

	if (!skey_data || IS_ERR(skey_data))
		return ERR_PTR(-EBADMSG);

	skey = key_alloc(&key_type_asymmetric, "s4_sign_key",
			GLOBAL_ROOT_UID, GLOBAL_ROOT_GID,
			cred, 0, KEY_ALLOC_NOT_IN_QUOTA);
	if (IS_ERR(skey)) {
		pr_err("PM: Allocate s4 sign key error: %ld\n", PTR_ERR(skey));
		goto error_keyalloc;
	}

	err = key_instantiate_and_link(skey, skey_data, skey_dsize, NULL, NULL);
	if (err < 0) {
		pr_err("PM: S4 sign key instantiate error: %d\n", err);
		if (skey)
			key_put(skey);
		skey = ERR_PTR(err);
		goto error_keyinit;
	}

	return skey;

error_keyinit:
error_keyalloc:
	return skey;
}

void erase_skey_data(void)
{
	if (!skey_data || IS_ERR(skey_data))
		return;

	memset(skey_data, 0, PAGE_SIZE);
}

void destroy_sign_key(struct key *skey)
{
	erase_skey_data();
	if (skey)
		key_put(skey);
}

static void *load_wake_key_data(unsigned long *datasize)
{
	u32 attr;
	void *wkey_data;
	efi_status_t status;

	if (!efi_enabled(EFI_RUNTIME_SERVICES))
		return ERR_PTR(-EPERM);

	/* obtain the size */
	*datasize = 0;
	status = efi.get_variable(EFI_S4_WAKE_KEY_NAME, &EFI_HIBERNATE_GUID,
				  NULL, datasize, NULL);
	if (status != EFI_BUFFER_TOO_SMALL) {
		wkey_data = ERR_PTR(efi_status_to_err(status));
		pr_err("PM: Couldn't get wake key data size: 0x%lx\n", status);
		goto error;
	}

	/* check attributes */
	wkey_data = kzalloc(*datasize, GFP_KERNEL);
	if (!wkey_data) {
		wkey_data = ERR_PTR(-ENOMEM);
		goto error;
	}

	status = efi.get_variable(EFI_S4_WAKE_KEY_NAME, &EFI_HIBERNATE_GUID,
				&attr, datasize, wkey_data);
	if (status) {
		kfree(wkey_data);
		*datasize = 0;
		wkey_data = ERR_PTR(efi_status_to_err(status));
		pr_err("PM: Get wake key data error: 0x%lx\n", status);
		goto error;
	}
	if (attr & EFI_VARIABLE_NON_VOLATILE) {
		memset(wkey_data, 0, *datasize);
		kfree(wkey_data);
		*datasize = 0;
		wkey_data = ERR_PTR(-EBADMSG);
		pr_err("PM: Wake key has wrong attributes: 0x%x\n", attr);
		goto error;
	}

error:
	return wkey_data;
}

bool wkey_data_available(void)
{
	static int ret = 1;
	unsigned long datasize;
	void *wkey_data;

	if (ret > 0) {
		wkey_data = load_wake_key_data(&datasize);
		if (wkey_data && IS_ERR(wkey_data)) {
			ret = PTR_ERR(wkey_data);
			goto error;
		} else {
			if (wkey_data) {
				memset(wkey_data, 0, datasize);
				kfree(wkey_data);
			}
			ret = 0;
		}
	}

error:
	return !ret;
}

struct key *get_wake_key(void)
{
	const struct cred *cred = current_cred();
	void *wkey_data;
	unsigned long datasize = 0;
	struct key *wkey;
	int err;

	wkey_data = load_wake_key_data(&datasize);
	if (IS_ERR(wkey_data)) {
		wkey = (struct key *)wkey_data;
		goto error_data;
	}

	wkey = key_alloc(&key_type_asymmetric, "s4_wake_key",
			GLOBAL_ROOT_UID, GLOBAL_ROOT_GID,
			cred, 0, KEY_ALLOC_NOT_IN_QUOTA);
	if (IS_ERR(wkey)) {
		pr_err("PM: Allocate s4 wake key error: %ld\n", PTR_ERR(wkey));
		goto error_keyalloc;
	}
	err = key_instantiate_and_link(wkey, wkey_data, datasize, NULL, NULL);
	if (err < 0) {
		pr_err("PM: S4 wake key instantiate error: %d\n", err);
		if (wkey)
			key_put(wkey);
		wkey = ERR_PTR(err);
	}

error_keyalloc:
	if (wkey_data && !IS_ERR(wkey_data))
		kfree(wkey_data);
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

static int __init init_sign_key_data(void)
{
	skey_data = (void *)get_zeroed_page(GFP_KERNEL);
	skey_data_buf = (void *)get_zeroed_page(GFP_KERNEL);

	if (skey_data && efi_s4_key_available()) {
		skey_dsize = efi_copy_skey_data(skey_data);
		efi_erase_s4_skey_data();
		pr_info("PM: Load s4 sign key from EFI\n");
	}

	return 0;
}

late_initcall(init_sign_key_data);

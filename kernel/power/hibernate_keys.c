#include <linux/sched.h>
#include <linux/efi.h>
#include <linux/mpi.h>
#include <linux/asn1.h>
#include <crypto/public_key.h>
#include <keys/asymmetric-type.h>

#include "power.h"

static unsigned char const_seq = (ASN1_SEQ | (ASN1_CONS << 5));

struct forward_info {
	struct forward_info_head        head;
	unsigned char                   skey_data_buf[SKEY_DBUF_MAX_SIZE];
};

static void *skey_data;
static void *forward_info_buf;
static unsigned long skey_dsize;

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

unsigned long get_sig_forward_info_pfn(void)
{
	if (!forward_info_buf)
		return 0;

	return page_to_pfn(virt_to_page(forward_info_buf));
}

void fill_sig_forward_info(void *page, int sig_check_ret_in)
{
	struct forward_info *info;

	if (!page)
		return;

	memset(page, 0, PAGE_SIZE);
	info = (struct forward_info *)page;

	info->head.sig_check_ret = sig_check_ret_in;
	if (skey_data && !IS_ERR(skey_data) &&
		skey_dsize <= SKEY_DBUF_MAX_SIZE) {
		info->head.skey_dsize = skey_dsize;
		memcpy(info->skey_data_buf, skey_data, skey_dsize);
	} else
		pr_info("PM: Fill S4 sign key fail, size: %ld\n", skey_dsize);

	pr_info("PM: Filled sign information to forward buffer\n");
}

void restore_sig_forward_info(void)
{
	struct forward_info *info;
	int sig_check_ret;

	if (!forward_info_buf) {
		pr_err("PM: Restore S4 sign key fail\n");
		return;
	}
	info = (struct forward_info *)forward_info_buf;

	sig_check_ret = info->head.sig_check_ret;
	if (sig_check_ret)
		pr_info("PM: Signature check fail: %d\n", sig_check_ret);

	if (info->head.skey_dsize <= SKEY_DBUF_MAX_SIZE &&
		info->skey_data_buf[0] == const_seq) {

		/* restore sign key size and data from buffer */
		skey_dsize = info->head.skey_dsize;
		memset(skey_data, 0, PAGE_SIZE);
		memcpy(skey_data, info->skey_data_buf, skey_dsize);
	}

	/* reset skey page buffer */
	memset(forward_info_buf, 0, PAGE_SIZE);
}

bool skey_data_available(void)
{
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
	struct efivar_entry *entry;
	u32 attr;
	void *wkey_data;
	int ret;

	entry = kmalloc(sizeof(*entry), GFP_KERNEL);
	if (!entry)
		return ERR_PTR(-ENOMEM);

	memcpy(entry->var.VariableName, EFI_S4_WAKE_KEY_NAME, sizeof(EFI_S4_WAKE_KEY_NAME));
	memcpy(&(entry->var.VendorGuid), &EFI_HIBERNATE_GUID, sizeof(efi_guid_t));

	/* obtain the size */
	*datasize = 0;
	ret = efivar_entry_size(entry, datasize);
	if (ret)
		goto error_size;

	wkey_data = kzalloc(*datasize, GFP_KERNEL);
	if (!wkey_data) {
		ret = -ENOMEM;
		goto error_size;
	}

	ret = efivar_entry_get(entry, &attr, datasize, wkey_data);
	if (ret) {
		pr_err("PM: Get wake key data error: %d\n", ret);
		goto error_get;
	}
	/* check attributes */
	if (attr & EFI_VARIABLE_NON_VOLATILE) {
		pr_err("PM: Wake key has wrong attributes: 0x%x\n", attr);
		goto error_get;
	}

	kfree(entry);

	return wkey_data;

error_get:
	memset(wkey_data, 0, *datasize);
	kfree(wkey_data);
	*datasize = 0;
error_size:
	kfree(entry);

	return ERR_PTR(ret);
}

int wkey_data_available(void)
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
	return ret;
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
	forward_info_buf = (void *)get_zeroed_page(GFP_KERNEL);

	if (skey_data && efi_s4_key_available()) {
		skey_dsize = efi_copy_skey_data(skey_data);
		efi_erase_s4_skey_data();
		pr_info("PM: Load s4 sign key from EFI\n");
	}

	return 0;
}

late_initcall(init_sign_key_data);

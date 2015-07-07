#include "misc.h"

#include <linux/efi.h>
#include <asm/archrandom.h>
#include <asm/efi.h>

static efi_status_t efi_locate_rng(efi_system_table_t *sys_table,
				   void ***rng_handle)
{
	efi_guid_t rng_proto = EFI_RNG_PROTOCOL_GUID;
	unsigned long size = 0;
	efi_status_t status;

	status = efi_call_early(locate_handle,
				EFI_LOCATE_BY_PROTOCOL,
				&rng_proto, NULL, &size, *rng_handle);

	if (status == EFI_BUFFER_TOO_SMALL) {
		status = efi_call_early(allocate_pool,
					EFI_LOADER_DATA,
					size, (void **)rng_handle);

		if (status != EFI_SUCCESS) {
			efi_printk(sys_table, " Failed to alloc mem for rng_handle");
			return status;
		}

		status = efi_call_early(locate_handle,
					EFI_LOCATE_BY_PROTOCOL, &rng_proto,
					NULL, &size, *rng_handle);
	}

	if (status != EFI_SUCCESS) {
		efi_printk(sys_table, " Failed to locate EFI_RNG_PROTOCOL");
		goto free_handle;
	}

	return EFI_SUCCESS;

free_handle:
	efi_call_early(free_pool, *rng_handle);

	return status;
}

static bool efi_rng_supported32(efi_system_table_t *sys_table, void **rng_handle)
{
	const struct efi_config *efi_early = __efi_early();
	efi_rng_protocol_32 *rng = NULL;
	efi_guid_t rng_proto = EFI_RNG_PROTOCOL_GUID;
	u32 *handles = (u32 *)(unsigned long)rng_handle;
	unsigned long size = 0;
	void **algorithmlist = NULL;
	efi_status_t status;

	status = efi_call_early(handle_protocol, handles[0],
				&rng_proto, (void **)&rng);
	if (status != EFI_SUCCESS)
		efi_printk(sys_table, " Failed to get EFI_RNG_PROTOCOL handles");

	if (status == EFI_SUCCESS && rng) {
		status = efi_early->call((unsigned long)rng->get_info, rng,
					&size, algorithmlist);
		return (status == EFI_BUFFER_TOO_SMALL);
	}

	return false;
}

static bool efi_rng_supported64(efi_system_table_t *sys_table, void **rng_handle)
{
	const struct efi_config *efi_early = __efi_early();
	efi_rng_protocol_64 *rng = NULL;
	efi_guid_t rng_proto = EFI_RNG_PROTOCOL_GUID;
	u64 *handles = (u64 *)(unsigned long)rng_handle;
	unsigned long size = 0;
	void **algorithmlist = NULL;
	efi_status_t status;

	status = efi_call_early(handle_protocol, handles[0],
				&rng_proto, (void **)&rng);
	if (status != EFI_SUCCESS)
		efi_printk(sys_table, " Failed to get EFI_RNG_PROTOCOL handles");

	if (status == EFI_SUCCESS && rng) {
		status = efi_early->call((unsigned long)rng->get_info, rng,
					&size, algorithmlist);
		return (status == EFI_BUFFER_TOO_SMALL);
	}

	return false;
}

static bool efi_rng_supported(efi_system_table_t *sys_table)
{
	const struct efi_config *efi_early = __efi_early();
	u32 random = 0;
	efi_status_t status;
	void **rng_handle = NULL;

	status = efi_locate_rng(sys_table, &rng_handle);
	if (status != EFI_SUCCESS)
		return false;

	if (efi_early->is64)
		random = efi_rng_supported64(sys_table, rng_handle);
	else
		random = efi_rng_supported32(sys_table, rng_handle);

	efi_call_early(free_pool, rng_handle);

	return random;

}

static unsigned long efi_get_rng32(efi_system_table_t *sys_table,
				   void **rng_handle)
{
	const struct efi_config *efi_early = __efi_early();
	efi_rng_protocol_32 *rng = NULL;
	efi_guid_t rng_proto = EFI_RNG_PROTOCOL_GUID;
	u32 *handles = (u32 *)(unsigned long)rng_handle;
	efi_status_t status;
	unsigned long rng_number = 0;

	status = efi_call_early(handle_protocol, handles[0],
				&rng_proto, (void **)&rng);
	if (status != EFI_SUCCESS)
		efi_printk(sys_table, " Failed to get EFI_RNG_PROTOCOL handles");

	if (status == EFI_SUCCESS && rng) {
		status = efi_early->call((unsigned long)rng->get_rng, rng, NULL,
					sizeof(rng_number), &rng_number);
		if (status != EFI_SUCCESS) {
			efi_printk(sys_table, " Failed to get RNG value ");
			efi_printk(sys_table, efi_status_to_str(status));
		}
	}

	return rng_number;
}

static unsigned long efi_get_rng64(efi_system_table_t *sys_table,
				   void **rng_handle)
{
	const struct efi_config *efi_early = __efi_early();
	efi_rng_protocol_64 *rng = NULL;
	efi_guid_t rng_proto = EFI_RNG_PROTOCOL_GUID;
	u64 *handles = (u64 *)(unsigned long)rng_handle;
	efi_status_t status;
	unsigned long rng_number;

	status = efi_call_early(handle_protocol, handles[0],
				&rng_proto, (void **)&rng);
	if (status != EFI_SUCCESS)
		efi_printk(sys_table, " Failed to get EFI_RNG_PROTOCOL handles");

	if (status == EFI_SUCCESS && rng) {
		status = efi_early->call((unsigned long)rng->get_rng, rng, NULL,
					sizeof(rng_number), &rng_number);
		if (status != EFI_SUCCESS) {
			efi_printk(sys_table, " Failed to get RNG value ");
			efi_printk(sys_table, efi_status_to_str(status));
		}
	}

	return rng_number;
}

static unsigned long efi_get_rng(efi_system_table_t *sys_table)
{
	const struct efi_config *efi_early = __efi_early();
	unsigned long random = 0;
	efi_status_t status;
	void **rng_handle = NULL;

	status = efi_locate_rng(sys_table, &rng_handle);
	if (status != EFI_SUCCESS)
		return 0;

	if (efi_early->is64)
		random = efi_get_rng64(sys_table, rng_handle);
	else
		random = efi_get_rng32(sys_table, rng_handle);

	efi_call_early(free_pool, rng_handle);

	return random;
}

#define X86_FEATURE_EDX_TSC	(1 << 4)
#define X86_FEATURE_ECX_RDRAND	(1 << 30)

static bool rdrand_feature(void)
{
	return (cpuid_ecx(0x1) & X86_FEATURE_ECX_RDRAND);
}

static bool rdtsc_feature(void)
{
	return (cpuid_edx(0x1) & X86_FEATURE_EDX_TSC);
}

static unsigned long get_random_long(unsigned long entropy,
				     struct boot_params *boot_params,
				     efi_system_table_t *sys_table)
{
#ifdef CONFIG_X86_64
	const unsigned long mix_const = 0x5d6008cbf3848dd3UL;
#else
	const unsigned long mix_const = 0x3f39e593UL;
#endif
	unsigned long raw, random;
	bool use_i8254 = true;

	efi_printk(sys_table, " EFI random");

	if (entropy)
		random = entropy;
	else
		random = get_random_boot(boot_params);

	if (rdrand_feature()) {
		efi_printk(sys_table, " RDRAND");
		if (rdrand_long(&raw)) {
			random ^= raw;
			use_i8254 = false;
		}
	}

	if (rdtsc_feature()) {
		efi_printk(sys_table, " RDTSC");
		rdtscll(raw);

		random ^= raw;
		use_i8254 = false;
	}

	if (efi_rng_supported(sys_table)) {
		efi_printk(sys_table, " EFI_RNG");
		raw = efi_get_rng(sys_table);
		if (raw)
			random ^= raw;
		use_i8254 = false;
	}

	if (use_i8254) {
		efi_printk(sys_table, " i8254");
		random ^= i8254();
	}

	/* Circular multiply for better bit diffusion */
	asm("mul %3"
	    : "=a" (random), "=d" (raw)
	    : "a" (random), "rm" (mix_const));
	random += raw;

	efi_printk(sys_table, "...\n");

	return random;
}

void efi_get_random_key(efi_system_table_t *sys_table,
			struct boot_params *params, u8 key[], int size)
{
	unsigned long entropy = 0;
	int i, bfill = size;

	if (key == NULL || !size)
		return;

	memset(key, 0, size);
	while (bfill > 0) {
		entropy = get_random_long(entropy, params, sys_table);
		if (bfill >= sizeof(entropy))
			memcpy((void *)(key + size - bfill), &entropy, sizeof(entropy));
		else
			memcpy((void *)(key + size - bfill), &entropy, bfill);
		bfill -= sizeof(entropy);
	}
}

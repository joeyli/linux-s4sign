#include "misc.h"

#include <linux/efi.h>
#include <asm/archrandom.h>

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

#ifdef CONFIG_X86_32
# include <asm/suspend_32.h>
#else
# include <asm/suspend_64.h>
#endif

#ifdef CONFIG_HIBERNATE_VERIFICATION
#include <linux/suspend.h>

struct swsusp_keys {
	unsigned long skey_status;
	u8 swsusp_key[SWSUSP_DIGEST_SIZE];
};
#endif

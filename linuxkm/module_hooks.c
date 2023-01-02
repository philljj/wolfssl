/* module_hooks.c -- module load/unload hooks for libwolfssl.ko
 *
 * Copyright (C) 2006-2022 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */

#ifndef WOLFSSL_LICENSE
#define WOLFSSL_LICENSE "GPL v2"
#endif

#define FIPS_NO_WRAPPERS

#define WOLFSSL_NEED_LINUX_CURRENT

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#ifdef WOLFCRYPT_ONLY
    #include <wolfssl/version.h>
#else
    #include <wolfssl/ssl.h>
#endif
#ifdef HAVE_FIPS
    #include <wolfssl/wolfcrypt/fips_test.h>
#endif
#ifndef NO_CRYPT_TEST
    #include <wolfcrypt/test/test.h>
    #include <linux/delay.h>
#endif

static int libwolfssl_cleanup(void) {
    int ret;
#ifdef WOLFCRYPT_ONLY
    ret = wolfCrypt_Cleanup();
    if (ret != 0)
        pr_err("wolfCrypt_Cleanup() failed: %s\n", wc_GetErrorString(ret));
    else
        pr_info("wolfCrypt " LIBWOLFSSL_VERSION_STRING " cleanup complete.\n");
#else
    ret = wolfSSL_Cleanup();
    if (ret != WOLFSSL_SUCCESS)
        pr_err("wolfSSL_Cleanup() failed: %s\n", wc_GetErrorString(ret));
    else
        pr_info("wolfSSL " LIBWOLFSSL_VERSION_STRING " cleanup complete.\n");
#endif

    return ret;
}

#ifdef HAVE_LINUXKM_PIE_SUPPORT

extern int wolfCrypt_PIE_first_function(void);
extern int wolfCrypt_PIE_last_function(void);
extern const unsigned int wolfCrypt_PIE_rodata_start[];
extern const unsigned int wolfCrypt_PIE_rodata_end[];

/* cheap portable ad-hoc hash function to confirm bitwise stability of the PIE
 * binary image.
 */
static unsigned int hash_span(char *start, char *end) {
    unsigned int sum = 1;
    while (start < end) {
        unsigned int rotate_by;
        sum ^= *start++;
        rotate_by = (sum ^ (sum >> 5)) & 31;
        sum = (sum << rotate_by) | (sum >> (32 - rotate_by));
    }
    return sum;
}

#ifdef USE_WOLFSSL_LINUXKM_PIE_REDIRECT_TABLE
extern struct wolfssl_linuxkm_pie_redirect_table wolfssl_linuxkm_pie_redirect_table;
static int set_up_wolfssl_linuxkm_pie_redirect_table(void);
#endif /* USE_WOLFSSL_LINUXKM_PIE_REDIRECT_TABLE */

#endif /* HAVE_LINUXKM_PIE_SUPPORT */

#ifdef HAVE_FIPS
static void lkmFipsCb(int ok, int err, const char* hash)
{
    if ((! ok) || (err != 0))
        pr_err("libwolfssl FIPS error: %s\n", wc_GetErrorString(err));
    if (err == IN_CORE_FIPS_E) {
        pr_err("In-core integrity hash check failure.\n"
               "Update verifyCore[] in fips_test.c with new hash \"%s\" and rebuild.\n",
               hash ? hash : "<null>");
    }
}
#endif

#ifdef WOLFCRYPT_FIPS_CORE_DYNAMIC_HASH_VALUE
#ifndef CONFIG_MODULE_SIG
#error WOLFCRYPT_FIPS_CORE_DYNAMIC_HASH_VALUE requires a CONFIG_MODULE_SIG kernel.
#endif
static int updateFipsHash(void);
#endif


#ifdef LINUXKM_REGISTER_ALG
#define WOLFKM_CBC_NAME   "cbc(aes)"
#define WOLFKM_GCM_NAME   "gcm(aes)"
#define WOLFKM_CBC_DRIVER "cbc-aes-wolfcrypt"
#define WOLFKM_GCM_DRIVER "gcm-aes-wolfcrypt"
#define WOLFKM_ALG_PRIORITY (100)
static int  linuxkm_register_alg(void);
static void linuxkm_unregister_alg(void);
    #ifdef LINUXKM_TEST_ALG
    static int linuxkm_test_alg(void);
    #endif
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
static int __init wolfssl_init(void)
#else
static int wolfssl_init(void)
#endif
{
    int ret;

#ifdef WOLFCRYPT_FIPS_CORE_DYNAMIC_HASH_VALUE
    if (THIS_MODULE->sig_ok == false) {
        pr_err("wolfSSL module load aborted -- bad or missing module signature with FIPS dynamic hash.\n");
        return -ECANCELED;
    }
    ret = updateFipsHash();
    if (ret < 0) {
        pr_err("wolfSSL module load aborted -- updateFipsHash: %s\n",wc_GetErrorString(ret));
        return -ECANCELED;
    }
#endif

#ifdef USE_WOLFSSL_LINUXKM_PIE_REDIRECT_TABLE
    ret = set_up_wolfssl_linuxkm_pie_redirect_table();
    if (ret < 0)
        return ret;
#endif

#ifdef HAVE_LINUXKM_PIE_SUPPORT

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 5, 0)
    #define THIS_MODULE_BASE (THIS_MODULE->core_layout.base)
    #define THIS_MODULE_TEXT_SIZE (THIS_MODULE->core_layout.text_size)
    #define THIS_MODULE_RO_SIZE (THIS_MODULE->core_layout.ro_size)
#else
    #define THIS_MODULE_BASE (THIS_MODULE->module_core)
    #define THIS_MODULE_TEXT_SIZE (THIS_MODULE->core_text_size)
    #define THIS_MODULE_RO_SIZE (THIS_MODULE->core_ro_size)
#endif

    {
        char *pie_text_start = (char *)wolfCrypt_PIE_first_function;
        char *pie_text_end = (char *)wolfCrypt_PIE_last_function;
        char *pie_rodata_start = (char *)wolfCrypt_PIE_rodata_start;
        char *pie_rodata_end = (char *)wolfCrypt_PIE_rodata_end;
        unsigned int text_hash, rodata_hash;

        if ((pie_text_start < pie_text_end) &&
            (pie_text_start >= (char *)THIS_MODULE_BASE) &&
            (pie_text_end - (char *)THIS_MODULE_BASE <= THIS_MODULE_TEXT_SIZE))
        {
            text_hash = hash_span(pie_text_start, pie_text_end);
        } else {
            pr_info("out-of-bounds PIE fenceposts! pie_text_start=%px pie_text_end=%px (span=%lu)"
                    " core_layout.base=%px text_end=%px\n",
                    pie_text_start,
                    pie_text_end,
                    pie_text_end-pie_text_start,
                    THIS_MODULE_BASE,
                    (char *)THIS_MODULE_BASE + THIS_MODULE_TEXT_SIZE);
            text_hash = 0;
        }

        if ((pie_rodata_start < pie_rodata_end) && // cppcheck-suppress comparePointers
            (pie_rodata_start >= (char *)THIS_MODULE_BASE + THIS_MODULE_TEXT_SIZE) &&
            (pie_rodata_end - (char *)THIS_MODULE_BASE <= THIS_MODULE_RO_SIZE))
        {
            rodata_hash = hash_span(pie_rodata_start, pie_rodata_end);
        } else {
            pr_info("out-of-bounds PIE fenceposts! pie_rodata_start=%px pie_rodata_end=%px (span=%lu)"
                    " core_layout.base+core_layout.text_size=%px rodata_end=%px\n",
                    pie_rodata_start,
                    pie_rodata_end,
                    pie_rodata_end-pie_rodata_start,
                    (char *)THIS_MODULE_BASE + THIS_MODULE_TEXT_SIZE,
                    (char *)THIS_MODULE_BASE + THIS_MODULE_RO_SIZE);
            rodata_hash = 0;
        }

        /* note, "%pK" conceals the actual layout information.  "%px" exposes
         * the true module start address, which is potentially useful to an
         * attacker.
         */
        pr_info("wolfCrypt container hashes (spans): %x (%lu) %x (%lu), module base %pK\n",
                text_hash, pie_text_end-pie_text_start,
                rodata_hash, pie_rodata_end-pie_rodata_start,
                THIS_MODULE_BASE);
    }
#endif /* HAVE_LINUXKM_PIE_SUPPORT */

#ifdef HAVE_FIPS
    ret = wolfCrypt_SetCb_fips(lkmFipsCb);
    if (ret != 0) {
        pr_err("wolfCrypt_SetCb_fips() failed: %s\n", wc_GetErrorString(ret));
        return -ECANCELED;
    }
    fipsEntry();
    ret = wolfCrypt_GetStatus_fips();
    if (ret != 0) {
        pr_err("wolfCrypt_GetStatus_fips() failed: %s\n", wc_GetErrorString(ret));
        if (ret == IN_CORE_FIPS_E) {
            const char *newhash = wolfCrypt_GetCoreHash_fips();
            pr_err("Update verifyCore[] in fips_test.c with new hash \"%s\" and rebuild.\n",
                   newhash ? newhash : "<null>");
        }
        return -ECANCELED;
    }

    pr_info("wolfCrypt FIPS ["

#if defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION == 3)
            "ready"
#elif defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION == 2) \
    && defined(WOLFCRYPT_FIPS_RAND)
            "140-2 rand"
#elif defined(HAVE_FIPS_VERSION) && (HAVE_FIPS_VERSION == 2)
            "140-2"
#else
            "140"
#endif
            "] POST succeeded.\n");
#endif /* HAVE_FIPS */

#ifdef WOLFCRYPT_ONLY
    ret = wolfCrypt_Init();
    if (ret != 0) {
        pr_err("wolfCrypt_Init() failed: %s\n", wc_GetErrorString(ret));
        return -ECANCELED;
    }
#else
    ret = wolfSSL_Init();
    if (ret != WOLFSSL_SUCCESS) {
        pr_err("wolfSSL_Init() failed: %s\n", wc_GetErrorString(ret));
        return -ECANCELED;
    }
#endif

#ifndef NO_CRYPT_TEST

#ifdef WC_RNG_SEED_CB
    ret = wc_SetSeed_Cb(wc_GenerateSeed);
    if (ret == 0)
#endif
    {
        ret = wolfcrypt_test(NULL);
    }
    if (ret < 0) {
        pr_err("wolfcrypt self-test failed with return code %d.\n", ret);
        (void)libwolfssl_cleanup();
        msleep(10);
        return -ECANCELED;
    }
    pr_info("wolfCrypt self-test passed.\n");
#endif

#ifdef WOLFCRYPT_ONLY
    pr_info("wolfCrypt " LIBWOLFSSL_VERSION_STRING " loaded%s"
            ".\nSee https://www.wolfssl.com/ for more information.\n"
            "wolfCrypt Copyright (C) 2006-present wolfSSL Inc.  Licensed under " WOLFSSL_LICENSE ".\n",
#ifdef CONFIG_MODULE_SIG
            THIS_MODULE->sig_ok ? " with valid module signature" : " without valid module signature"
#else
            ""
#endif
        );
#else
    pr_info("wolfSSL " LIBWOLFSSL_VERSION_STRING " loaded%s"
            ".\nSee https://www.wolfssl.com/ for more information.\n"
            "wolfSSL Copyright (C) 2006-present wolfSSL Inc.  Licensed under " WOLFSSL_LICENSE ".\n",
#ifdef CONFIG_MODULE_SIG
            THIS_MODULE->sig_ok ? " with valid module signature" : " without valid module signature"
#else
            ""
#endif
        );
#endif

#ifdef LINUXKM_REGISTER_ALG
    ret = linuxkm_register_alg();

    if (ret) {
        pr_err("linuxkm_register_alg failed with return code %d.\n", ret);
        (void)libwolfssl_cleanup();
        msleep(10);
        return -ECANCELED;
    }

    #ifdef LINUXKM_TEST_ALG
    ret = linuxkm_test_alg();

    if (ret) {
        pr_err("linuxkm_test_alg failed with return code %d.\n", ret);
        /* (void)libwolfssl_cleanup();
        msleep(10);
        return -ECANCELED; */
    }
    #endif
#endif
    return 0;
}

module_init(wolfssl_init);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 0, 0)
static void __exit wolfssl_exit(void)
#else
static void wolfssl_exit(void)
#endif
{
    (void)libwolfssl_cleanup();

#ifdef LINUXKM_REGISTER_ALG
    linuxkm_unregister_alg();
#endif
    return;
}

module_exit(wolfssl_exit);

MODULE_LICENSE(WOLFSSL_LICENSE);
MODULE_AUTHOR("https://www.wolfssl.com/");
MODULE_DESCRIPTION("libwolfssl cryptographic and protocol facilities");
MODULE_VERSION(LIBWOLFSSL_VERSION_STRING);

#ifdef USE_WOLFSSL_LINUXKM_PIE_REDIRECT_TABLE

/* get_current() is an inline or macro, depending on the target -- sidestep the whole issue with a wrapper func. */
static struct task_struct *my_get_current_thread(void) {
    return get_current();
}

/* ditto for preempt_count(). */
static int my_preempt_count(void) {
    return preempt_count();
}

#if defined(WOLFSSL_LINUXKM_SIMD_X86) && (LINUX_VERSION_CODE < KERNEL_VERSION(5, 14, 0))
static int my_copy_fpregs_to_fpstate(struct fpu *fpu) {
    return copy_fpregs_to_fpstate(fpu);
}
static void my_copy_kernel_to_fpregs(union fpregs_state *fpstate) {
    copy_kernel_to_fpregs(fpstate);
}
#endif

static int set_up_wolfssl_linuxkm_pie_redirect_table(void) {
    memset(
        &wolfssl_linuxkm_pie_redirect_table,
        0,
        sizeof wolfssl_linuxkm_pie_redirect_table);

#ifndef __ARCH_MEMCMP_NO_REDIRECT
    wolfssl_linuxkm_pie_redirect_table.memcmp = memcmp;
#endif
#ifndef __ARCH_MEMCPY_NO_REDIRECT
    wolfssl_linuxkm_pie_redirect_table.memcpy = memcpy;
#endif
#ifndef __ARCH_MEMSET_NO_REDIRECT
    wolfssl_linuxkm_pie_redirect_table.memset = memset;
#endif
#ifndef __ARCH_MEMMOVE_NO_REDIRECT
    wolfssl_linuxkm_pie_redirect_table.memmove = memmove;
#endif
#ifndef __ARCH_STRCMP_NO_REDIRECT
    wolfssl_linuxkm_pie_redirect_table.strcmp = strcmp;
#endif
#ifndef __ARCH_STRNCMP_NO_REDIRECT
    wolfssl_linuxkm_pie_redirect_table.strncmp = strncmp;
#endif
#ifndef __ARCH_STRCASECMP_NO_REDIRECT
    wolfssl_linuxkm_pie_redirect_table.strcasecmp = strcasecmp;
#endif
#ifndef __ARCH_STRNCASECMP_NO_REDIRECT
    wolfssl_linuxkm_pie_redirect_table.strncasecmp = strncasecmp;
#endif
#ifndef __ARCH_STRLEN_NO_REDIRECT
    wolfssl_linuxkm_pie_redirect_table.strlen = strlen;
#endif
#ifndef __ARCH_STRSTR_NO_REDIRECT
    wolfssl_linuxkm_pie_redirect_table.strstr = strstr;
#endif
#ifndef __ARCH_STRNCPY_NO_REDIRECT
    wolfssl_linuxkm_pie_redirect_table.strncpy = strncpy;
#endif
#ifndef __ARCH_STRNCAT_NO_REDIRECT
    wolfssl_linuxkm_pie_redirect_table.strncat = strncat;
#endif
    wolfssl_linuxkm_pie_redirect_table.kstrtoll = kstrtoll;

    #if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 15, 0)
        wolfssl_linuxkm_pie_redirect_table._printk = _printk;
    #else
        wolfssl_linuxkm_pie_redirect_table.printk = printk;
    #endif
    wolfssl_linuxkm_pie_redirect_table.snprintf = snprintf;

    wolfssl_linuxkm_pie_redirect_table._ctype = _ctype;

    wolfssl_linuxkm_pie_redirect_table.kmalloc = kmalloc;
    wolfssl_linuxkm_pie_redirect_table.kfree = kfree;
    wolfssl_linuxkm_pie_redirect_table.ksize = ksize;
    wolfssl_linuxkm_pie_redirect_table.krealloc = krealloc;
#ifdef HAVE_KVMALLOC
    wolfssl_linuxkm_pie_redirect_table.kvmalloc_node = kvmalloc_node;
    wolfssl_linuxkm_pie_redirect_table.kvfree = kvfree;
#endif
    wolfssl_linuxkm_pie_redirect_table.is_vmalloc_addr = is_vmalloc_addr;
    #if LINUX_VERSION_CODE >= KERNEL_VERSION(6, 1, 0)
        wolfssl_linuxkm_pie_redirect_table.kmalloc_trace =
            kmalloc_trace;
    #else
        wolfssl_linuxkm_pie_redirect_table.kmem_cache_alloc_trace =
            kmem_cache_alloc_trace;
        wolfssl_linuxkm_pie_redirect_table.kmalloc_order_trace =
            kmalloc_order_trace;
    #endif

    wolfssl_linuxkm_pie_redirect_table.get_random_bytes = get_random_bytes;
    #if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)
        wolfssl_linuxkm_pie_redirect_table.getnstimeofday =
            getnstimeofday;
    #elif LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0)
        wolfssl_linuxkm_pie_redirect_table.current_kernel_time64 =
            current_kernel_time64;
    #else
        wolfssl_linuxkm_pie_redirect_table.ktime_get_coarse_real_ts64 =
            ktime_get_coarse_real_ts64;
    #endif

    wolfssl_linuxkm_pie_redirect_table.get_current = my_get_current_thread;
    wolfssl_linuxkm_pie_redirect_table.preempt_count = my_preempt_count;

#ifdef WOLFSSL_LINUXKM_SIMD_X86
    wolfssl_linuxkm_pie_redirect_table.irq_fpu_usable = irq_fpu_usable;
    #ifdef kernel_fpu_begin
    wolfssl_linuxkm_pie_redirect_table.kernel_fpu_begin_mask =
        kernel_fpu_begin_mask;
    #else
    wolfssl_linuxkm_pie_redirect_table.kernel_fpu_begin =
        kernel_fpu_begin;
    #endif
    wolfssl_linuxkm_pie_redirect_table.kernel_fpu_end = kernel_fpu_end;
    #ifdef LINUXKM_SIMD_IRQ
        #if LINUX_VERSION_CODE < KERNEL_VERSION(5, 14, 0)
            wolfssl_linuxkm_pie_redirect_table.copy_fpregs_to_fpstate = my_copy_fpregs_to_fpstate;
            wolfssl_linuxkm_pie_redirect_table.copy_kernel_to_fpregs = my_copy_kernel_to_fpregs;
        #elif LINUX_VERSION_CODE < KERNEL_VERSION(5, 16, 0)
            wolfssl_linuxkm_pie_redirect_table.save_fpregs_to_fpstate = save_fpregs_to_fpstate;
            wolfssl_linuxkm_pie_redirect_table.__restore_fpregs_from_fpstate = __restore_fpregs_from_fpstate;
            wolfssl_linuxkm_pie_redirect_table.xfeatures_mask_all = &xfeatures_mask_all;
        /*
         * #else
         *  wolfssl_linuxkm_pie_redirect_table.save_fpregs_to_fpstate = save_fpregs_to_fpstate;
         *  wolfssl_linuxkm_pie_redirect_table.restore_fpregs_from_fpstate = restore_fpregs_from_fpstate;
         *  wolfssl_linuxkm_pie_redirect_table.fpu_kernel_cfg = &fpu_kernel_cfg;
         */
        #endif
    #endif
    wolfssl_linuxkm_pie_redirect_table.cpu_number = &cpu_number;
    wolfssl_linuxkm_pie_redirect_table.nr_cpu_ids = &nr_cpu_ids;
#endif

    wolfssl_linuxkm_pie_redirect_table.__mutex_init = __mutex_init;
    #if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)
        wolfssl_linuxkm_pie_redirect_table.mutex_lock_nested = mutex_lock_nested;
    #else
        wolfssl_linuxkm_pie_redirect_table.mutex_lock = mutex_lock;
    #endif
    wolfssl_linuxkm_pie_redirect_table.mutex_unlock = mutex_unlock;
    #if LINUX_VERSION_CODE < KERNEL_VERSION(4, 0, 0)
        wolfssl_linuxkm_pie_redirect_table.mutex_destroy = mutex_destroy;
    #endif

#ifdef HAVE_FIPS
    wolfssl_linuxkm_pie_redirect_table.wolfCrypt_FIPS_first =
        wolfCrypt_FIPS_first;
    wolfssl_linuxkm_pie_redirect_table.wolfCrypt_FIPS_last =
        wolfCrypt_FIPS_last;
#endif

#if !defined(WOLFCRYPT_ONLY) && !defined(NO_CERTS)
    wolfssl_linuxkm_pie_redirect_table.GetCA = GetCA;
#ifndef NO_SKID
    wolfssl_linuxkm_pie_redirect_table.GetCAByName = GetCAByName;
#endif
#endif

    /* runtime assert that the table has no null slots after initialization. */
    {
        unsigned long *i;
        for (i = (unsigned long *)&wolfssl_linuxkm_pie_redirect_table;
             i < (unsigned long *)&wolfssl_linuxkm_pie_redirect_table._last_slot;
             ++i)
            if (*i == 0) {
                pr_err("wolfCrypt container redirect table initialization was incomplete.\n");
                return -EFAULT;
            }
    }

    return 0;
}

#endif /* USE_WOLFSSL_LINUXKM_PIE_REDIRECT_TABLE */


#ifdef WOLFCRYPT_FIPS_CORE_DYNAMIC_HASH_VALUE

#include <wolfssl/wolfcrypt/coding.h>

PRAGMA_GCC_DIAG_PUSH;
PRAGMA_GCC("GCC diagnostic ignored \"-Wnested-externs\"");
PRAGMA_GCC("GCC diagnostic ignored \"-Wpointer-arith\"");
#include <crypto/hash.h>
PRAGMA_GCC_DIAG_POP;

extern char verifyCore[WC_SHA256_DIGEST_SIZE*2 + 1];
extern const char coreKey[WC_SHA256_DIGEST_SIZE*2 + 1];
extern const unsigned int wolfCrypt_FIPS_ro_start[];
extern const unsigned int wolfCrypt_FIPS_ro_end[];

#define FIPS_IN_CORE_KEY_SZ 32
#define FIPS_IN_CORE_VERIFY_SZ FIPS_IN_CORE_KEY_SZ
typedef int (*fips_address_function)(void);
#define MAX_FIPS_DATA_SZ  100000
#define MAX_FIPS_CODE_SZ 1000000
extern int GenBase16_Hash(const byte* in, int length, char* out, int outSz);

static int updateFipsHash(void)
{
    struct crypto_shash *tfm = NULL;
    struct shash_desc *desc = NULL;
    word32 verifySz  = FIPS_IN_CORE_VERIFY_SZ;
    word32 binCoreSz  = FIPS_IN_CORE_KEY_SZ;
    int ret;
    byte *hash = NULL;
    char *base16_hash = NULL;
    byte *binCoreKey = NULL;
    byte *binVerify = NULL;

    fips_address_function first = wolfCrypt_FIPS_first;
    fips_address_function last  = wolfCrypt_FIPS_last;

    char* start = (char*)wolfCrypt_FIPS_ro_start;
    char* end   = (char*)wolfCrypt_FIPS_ro_end;

    unsigned long code_sz = (unsigned long)last - (unsigned long)first;
    unsigned long data_sz = (unsigned long)end - (unsigned long)start;

    if (data_sz == 0 || data_sz > MAX_FIPS_DATA_SZ)
        return BAD_FUNC_ARG;  /* bad fips data size */

    if (code_sz == 0 || code_sz > MAX_FIPS_CODE_SZ)
        return BAD_FUNC_ARG;  /* bad fips code size */

    hash = XMALLOC(WC_SHA256_DIGEST_SIZE, 0, DYNAMIC_TYPE_TMP_BUFFER);
    if (hash == NULL) {
        ret = MEMORY_E;
        goto out;
    }
    base16_hash = XMALLOC(WC_SHA256_DIGEST_SIZE*2 + 1, 0, DYNAMIC_TYPE_TMP_BUFFER);
    if (base16_hash == NULL) {
        ret = MEMORY_E;
        goto out;
    }
    binCoreKey = XMALLOC(binCoreSz, 0, DYNAMIC_TYPE_TMP_BUFFER);
    if (binCoreKey == NULL) {
        ret = MEMORY_E;
        goto out;
    }
    binVerify = XMALLOC(verifySz, 0, DYNAMIC_TYPE_TMP_BUFFER);
    if (binVerify == NULL) {
        ret = MEMORY_E;
        goto out;
    }

    {
        word32 base16_out_len = binCoreSz;
        ret = Base16_Decode((const byte *)coreKey, sizeof coreKey - 1, binCoreKey, &base16_out_len);
        if (ret != 0) {
            pr_err("Base16_Decode for coreKey: %s\n", wc_GetErrorString(ret));
            goto out;
        }
        if (base16_out_len != binCoreSz) {
            pr_err("unexpected output length %u for coreKey from Base16_Decode.\n",base16_out_len);
            ret = BAD_STATE_E;
            goto out;
        }
    }

    tfm = crypto_alloc_shash("hmac(sha256)", 0, 0);
    if (IS_ERR(tfm)) {
        if (PTR_ERR(tfm) == -ENOMEM) {
            pr_err("crypto_alloc_shash failed: out of memory\n");
            ret = MEMORY_E;
        } else if (PTR_ERR(tfm) == -ENOENT) {
            pr_err("crypto_alloc_shash failed: kernel is missing hmac(sha256) implementation\n");
            pr_err("check for CONFIG_CRYPTO_SHA256 and CONFIG_CRYPTO_HMAC.\n");
            ret = NOT_COMPILED_IN;
        } else {
            pr_err("crypto_alloc_shash failed with ret %ld\n",PTR_ERR(tfm));
            ret = HASH_TYPE_E;
        }
        tfm = NULL;
        goto out;
    }

    {
        size_t desc_size = crypto_shash_descsize(tfm) + sizeof *desc;
        desc = XMALLOC(desc_size, NULL, DYNAMIC_TYPE_TMP_BUFFER);
        if (desc == NULL) {
            pr_err("failed allocating desc.");
            ret = MEMORY_E;
            goto out;
        }
        XMEMSET(desc, 0, desc_size);
    }

    ret = crypto_shash_setkey(tfm, binCoreKey, binCoreSz);
    if (ret) {
        pr_err("crypto_ahash_setkey failed: err %d\n", ret);
        ret = BAD_STATE_E;
        goto out;
    }

    desc->tfm = tfm;
    ret = crypto_shash_init(desc);
    if (ret) {
        pr_err("crypto_shash_init failed: err %d\n", ret);
        ret = BAD_STATE_E;
        goto out;
    }

    ret = crypto_shash_update(desc, (byte *)(wc_ptr_t)first, (word32)code_sz);
    if (ret) {
        pr_err("crypto_shash_update failed: err %d\n", ret);
        ret = BAD_STATE_E;
        goto out;
    }

    /* don't hash verifyCore or changing verifyCore will change hash */
    if (verifyCore >= start && verifyCore < end) {
        data_sz = (unsigned long)verifyCore - (unsigned long)start;
        ret = crypto_shash_update(desc, (byte*)start, (word32)data_sz);
        if (ret) {
                pr_err("crypto_shash_update failed: err %d\n", ret);
                ret = BAD_STATE_E;
                goto out;
        }
        start   = (char*)verifyCore + sizeof(verifyCore);
        data_sz = (unsigned long)end - (unsigned long)start;
    }
    ret = crypto_shash_update(desc, (byte*)start, (word32)data_sz);
    if (ret) {
        pr_err("crypto_shash_update failed: err %d\n", ret);
        ret = BAD_STATE_E;
        goto out;
    }

    ret = crypto_shash_final(desc, hash);
    if (ret) {
        pr_err("crypto_shash_final failed: err %d\n", ret);
        ret = BAD_STATE_E;
        goto out;
    }

    ret = GenBase16_Hash(hash, WC_SHA256_DIGEST_SIZE, base16_hash, WC_SHA256_DIGEST_SIZE*2 + 1);
    if (ret != 0) {
        pr_err("GenBase16_Hash failed: %s\n", wc_GetErrorString(ret));
        goto out;
    }

    {
        word32 base16_out_len = verifySz;
        ret = Base16_Decode((const byte *)verifyCore, sizeof verifyCore - 1, binVerify, &base16_out_len);
        if (ret != 0) {
            pr_err("Base16_Decode for verifyCore: %s\n", wc_GetErrorString(ret));
            goto out;
        }
        if (base16_out_len != binCoreSz) {
            pr_err("unexpected output length %u for verifyCore from Base16_Decode.\n",base16_out_len);
            ret = BAD_STATE_E;
            goto out;
        }
    }

    if (XMEMCMP(hash, binVerify, WC_SHA256_DIGEST_SIZE) == 0)
        pr_info("updateFipsHash: verifyCore already matches.\n");
    else {
        XMEMCPY(verifyCore, base16_hash, WC_SHA256_DIGEST_SIZE*2 + 1);
        pr_info("updateFipsHash: verifyCore updated.\n");
    }

    ret = 0;

  out:

    if (tfm != NULL)
        crypto_free_shash(tfm);
    if (desc != NULL)
        XFREE(desc, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (hash != NULL)
        XFREE(hash, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (base16_hash != NULL)
        XFREE(base16_hash, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (binCoreKey != NULL)
        XFREE(binCoreKey, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    if (binVerify != NULL)
        XFREE(binVerify, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    return ret;
}

#endif /* WOLFCRYPT_FIPS_CORE_DYNAMIC_HASH_VALUE */


#ifdef LINUXKM_REGISTER_ALG
#include <linux/crypto.h>

PRAGMA_GCC_DIAG_PUSH;
PRAGMA_GCC("GCC diagnostic ignored \"-Wnested-externs\"");
PRAGMA_GCC("GCC diagnostic ignored \"-Wpointer-arith\"");
PRAGMA_GCC("GCC diagnostic ignored \"-Wpointer-sign\"");
PRAGMA_GCC("GCC diagnostic ignored \"-Wbad-function-cast\"");
PRAGMA_GCC("GCC diagnostic ignored \"-Wunused-parameter\"");
#include <linux/scatterlist.h>
#include <crypto/scatterwalk.h>
#include <crypto/internal/aead.h>
#include <crypto/internal/skcipher.h>
PRAGMA_GCC_DIAG_POP;

/* km_AesX(): wrappers to wolfcrypt wc_AesX functions and
 * structures.  */

struct km_AesCtx {
    Aes          aes;
    u8           key[AES_MAX_KEY_SIZE / 8];
    unsigned int keylen;
};

static inline void km_ForceZero(struct km_AesCtx * ctx)
{
    /* using kernel force memzero because this is kernel code */
    memzero_explicit(ctx->key, sizeof(ctx->key));
    ctx->keylen = 0;
}

static int km_AesInitCommon(struct km_AesCtx * ctx, const char * name)
{
    int err = wc_AesInit(&ctx->aes, NULL, INVALID_DEVID);

    if (unlikely(err)) {
        pr_err("error: km_AesInitCommon %s failed: %d\n", name, err);
        return err;
    }

    pr_info("info: km_AesInitCommon %s good\n", name);
    return 0;
}

static void km_AesExitCommon(struct km_AesCtx * ctx, const char * name)
{
    wc_AesFree(&ctx->aes);
    km_ForceZero(ctx);
    pr_info("info: km_AesExitCommon %s\n", name);
}

static int km_AesSetKeyCommon(struct km_AesCtx * ctx, const u8 *in_key,
                              unsigned int key_len, const char * name)
{
    int err = wc_AesSetKey(&ctx->aes, in_key, key_len, NULL, 0);

    if (unlikely(err)) {
        pr_err("error: km_AesSetKeyCommon %s failed: %d\n", name, err);
        return err;
    }

    XMEMCPY(ctx->key, in_key, key_len);
    ctx->keylen = key_len;

    pr_info("info: km_AesSetKeyCommon %s: ctx->keylen: %d\n", name,
            ctx->keylen);
    return 0;
}

static int km_AesInit(struct crypto_skcipher *tfm)
{
    struct km_AesCtx * ctx = crypto_skcipher_ctx(tfm);
    return km_AesInitCommon(ctx, WOLFKM_CBC_DRIVER);
}

static void km_AesExit(struct crypto_skcipher *tfm)
{
    struct km_AesCtx * ctx = crypto_skcipher_ctx(tfm);
    km_AesExitCommon(ctx, WOLFKM_CBC_DRIVER);
}

static int km_AesSetKey(struct crypto_skcipher *tfm, const u8 *in_key,
                          unsigned int key_len)
{
    struct km_AesCtx * ctx = crypto_skcipher_ctx(tfm);
    return km_AesSetKeyCommon(ctx, in_key, key_len, WOLFKM_CBC_DRIVER);
}

static int km_AesCbcEncrypt(struct skcipher_request *req)
{
    struct crypto_skcipher * tfm = NULL;
    struct km_AesCtx *       ctx = NULL;
    struct skcipher_walk     walk;
    unsigned int             nbytes = 0;
    int                      err = 0;

    tfm = crypto_skcipher_reqtfm(req);
    ctx = crypto_skcipher_ctx(tfm);

    err = skcipher_walk_virt(&walk, req, false);

    while ((nbytes = walk.nbytes)) {
        pr_info("info: walk.nbytes: %d\n", walk.nbytes);
        pr_info("info: ctx->keylen: %d\n", ctx->keylen);

        err = wc_AesSetKey(&ctx->aes, ctx->key, ctx->keylen, walk.iv,
                           AES_ENCRYPTION);

        if (unlikely(err)) {
            pr_err("wc_AesSetKey failed: %d\n", err);
            return err;
        }

        err = wc_AesCbcEncrypt(&ctx->aes, walk.dst.virt.addr,
                               walk.src.virt.addr, nbytes);

        if (unlikely(err)) {
            pr_err("wc_AesCbcEncrypt failed %d\n", err);
            return err;
        }

        err = skcipher_walk_done(&walk, walk.nbytes - nbytes);
    }

    return err;
}

static int km_AesCbcDecrypt(struct skcipher_request *req)
{
    struct crypto_skcipher * tfm = NULL;
    struct km_AesCtx *       ctx = NULL;
    struct skcipher_walk     walk;
    unsigned int             nbytes = 0;
    int                      err = 0;

    tfm = crypto_skcipher_reqtfm(req);
    ctx = crypto_skcipher_ctx(tfm);

    err = skcipher_walk_virt(&walk, req, false);

    while ((nbytes = walk.nbytes)) {
        err = wc_AesSetKey(&ctx->aes, ctx->key, ctx->keylen, walk.iv,
                           AES_DECRYPTION);

        if (unlikely(err)) {
            pr_err("wc_AesSetKey failed");
            return err;
        }

        err = wc_AesCbcDecrypt(&ctx->aes, walk.dst.virt.addr,
                               walk.src.virt.addr, nbytes);

        if (unlikely(err)) {
            pr_err("wc_AesCbcDecrypt failed");
            return err;
        }

        err = skcipher_walk_done(&walk, walk.nbytes - nbytes);
    }

    return err;
}

static int km_AesGcmInit(struct crypto_aead * tfm)
{
    struct km_AesCtx * ctx = crypto_aead_ctx(tfm);
    km_ForceZero(ctx);
    return km_AesInitCommon(ctx, WOLFKM_GCM_DRIVER);
}

static void km_AesGcmExit(struct crypto_aead * tfm)
{
    struct km_AesCtx * ctx = crypto_aead_ctx(tfm);
    km_AesExitCommon(ctx, WOLFKM_GCM_DRIVER);
}

static int km_AesGcmSetKey(struct crypto_aead *tfm, const u8 *in_key,
                           unsigned int key_len)
{
    struct km_AesCtx * ctx = crypto_aead_ctx(tfm);
    return km_AesSetKeyCommon(ctx, in_key, key_len, WOLFKM_GCM_DRIVER);
}

static int km_AesGcmSetAuthsize(struct crypto_aead *tfm, unsigned int authsize)
{
    (void)tfm;
    if (authsize > AES_BLOCK_SIZE ||
        authsize < WOLFSSL_MIN_AUTH_TAG_SZ) {
        pr_err("error: authsize invalid size: %d\n", authsize);
        return -EINVAL;
    }
    return 0;
}


static int km_AesGcmEncrypt(struct aead_request *req)
{
    struct crypto_aead * tfm = NULL;
    struct km_AesCtx *   ctx = NULL;
    struct skcipher_walk walk;
    struct scatter_walk  authInWalk;
    unsigned long        authTagSz = 0;
    unsigned long        authInSz = 0;
    unsigned int         nbytes = 0;
    u8                   authTag[AES_BLOCK_SIZE];
    u8 *                 authIn = NULL;
    u8 *                 authInMem = NULL;
    int                  err = 0;

    tfm = crypto_aead_reqtfm(req);
    ctx = crypto_aead_ctx(tfm);
    authTagSz = tfm->authsize;
    authInSz = req->assoclen;

    err = skcipher_walk_aead_encrypt(&walk, req, false);

    if (unlikely(err)) {
        pr_err("error: skcipher_walk_aead_encrypt: %d\n", err);
        return -1;
    }

    /*
     * encrypt
     *   req->src: aad||plaintext
     *   req->dst: aad||ciphertext||tag
     * decrypt
     *   req->src: aad||ciphertext||tag
     *   req->dst: aad||plaintext, return 0 or -EBADMSG
     * aad, plaintext and ciphertext may be empty.
     */

    if (req->src->length >= authInSz) {
        /* All the associated data is within the first scatterlist, just
         * map to buffer pointer. */
        scatterwalk_start(&authInWalk, req->src);
        authIn = scatterwalk_map(&authInWalk);
    }
    else {
        /* Associated data larger than first scatterlist, must alloc buffer. */
        authInMem = kmalloc(authInSz, GFP_KERNEL);

        if (unlikely(!authInMem)) {
            pr_err("error: kmalloc(%ld, GFP_KERNEL) failed\n", authInSz);
            return -ENOMEM;
        }

        authIn = authInMem;
        scatterwalk_map_and_copy(authIn, req->src, 0, authInSz, 0);
    }

    err = skcipher_walk_aead_encrypt(&walk, req, false);

    while ((nbytes = walk.nbytes)) {
        pr_info("info: walk.nbytes: %d\n", walk.nbytes);
        pr_info("info: ctx->keylen: %d\n", ctx->keylen);

        err = wc_AesSetKey(&ctx->aes, ctx->key, ctx->keylen, walk.iv,
                           AES_ENCRYPTION);

        if (unlikely(err)) {
            pr_err("wc_AesSetKey failed: %d\n", err);
            return err;
        }

        err = wc_AesGcmEncrypt(&ctx->aes,
                               walk.dst.virt.addr, walk.src.virt.addr,
                               nbytes, walk.iv, walk.ivsize,
                               authTag, authTagSz, authIn, authInSz);

        if (unlikely(err)) {
            pr_err("wc_AesCbcEncrypt failed %d\n", err);
            return err;
        }

        err = skcipher_walk_done(&walk, walk.nbytes - nbytes);
    }

    /* Now copy the auth tag into request scatterlist. */
    scatterwalk_map_and_copy(authTag, req->dst,
                             req->assoclen + req->cryptlen,
                             authTagSz, 1);

    return err;
}

static int km_AesGcmDecrypt(struct aead_request *req)
{
    struct crypto_aead * tfm = NULL;
    struct km_AesCtx *   ctx = NULL;
    struct skcipher_walk walk;
    struct scatter_walk  authInWalk;
    unsigned long        authTagSz = 0;
    unsigned long        authInSz = 0;
    unsigned int         nbytes = 0;
    u8                   authTag[AES_BLOCK_SIZE];
    u8                   origAuthTag[AES_BLOCK_SIZE];
    u8 *                 authIn = NULL;
    u8 *                 authInMem = NULL;
    int                  err = 0;

    tfm = crypto_aead_reqtfm(req);
    ctx = crypto_aead_ctx(tfm);
    authTagSz = tfm->authsize;
    authInSz = req->assoclen;

    err = skcipher_walk_aead_encrypt(&walk, req, false);

    if (unlikely(err)) {
        pr_err("error: skcipher_walk_aead_encrypt: %d\n", err);
        return -1;
    }

    /*
     * encrypt
     *   req->src: aad||plaintext
     *   req->dst: aad||ciphertext||tag
     * decrypt
     *   req->src: aad||ciphertext||tag
     *   req->dst: aad||plaintext, return 0 or -EBADMSG
     * aad, plaintext and ciphertext may be empty.
     */

    if (req->src->length >= authInSz) {
        /* All the associated data is within the first scatterlist, just
         * map to buffer pointer. */
        scatterwalk_start(&authInWalk, req->src);
        authIn = scatterwalk_map(&authInWalk);
    }
    else {
        /* Associated data larger than first scatterlist, must alloc buffer. */
        authInMem = kmalloc(authInSz, GFP_KERNEL);

        if (unlikely(!authInMem)) {
            pr_err("error: kmalloc(%ld, GFP_KERNEL) failed\n", authInSz);
            return -ENOMEM;
        }

        authIn = authInMem;
        scatterwalk_map_and_copy(authIn, req->src, 0, authInSz, 0);
    }

    err = skcipher_walk_aead_decrypt(&walk, req, false);

    while ((nbytes = walk.nbytes)) {
        pr_info("info: walk.nbytes: %d\n", walk.nbytes);
        pr_info("info: ctx->keylen: %d\n", ctx->keylen);

        err = wc_AesSetKey(&ctx->aes, ctx->key, ctx->keylen, walk.iv,
                           AES_DECRYPTION);

        if (unlikely(err)) {
            pr_err("wc_AesSetKey failed: %d\n", err);
            return err;
        }

        err = wc_AesGcmDecrypt(&ctx->aes,
                               walk.dst.virt.addr, walk.src.virt.addr,
                               nbytes, walk.iv, walk.ivsize,
                               authTag, authTagSz, authIn, authInSz);

        if (unlikely(err)) {
            pr_err("wc_AesCbcEncrypt failed %d\n", err);
            return err;
        }

        err = skcipher_walk_done(&walk, walk.nbytes - nbytes);
    }

    /* Copy out original auth tag from req->src. */
    scatterwalk_map_and_copy(origAuthTag, req->src,
                             req->assoclen + req->cryptlen - authTagSz,
                             authTagSz, 0);

    /* Compare against generated tag. */
    if (crypto_memneq(origAuthTag, authTag, authTagSz)) {
        memzero_explicit(authTag, authTagSz);
        return -EBADMSG;
    }

    return err;
}

static struct skcipher_alg cbcAesAlg = {
    .base.cra_name        = WOLFKM_CBC_NAME,
    .base.cra_driver_name = WOLFKM_CBC_DRIVER,
    .base.cra_priority    = WOLFKM_ALG_PRIORITY,
    .base.cra_blocksize   = AES_BLOCK_SIZE,
    .base.cra_ctxsize     = sizeof(struct km_AesCtx),
    .base.cra_module      = THIS_MODULE,
    .init                 = km_AesInit,
    .exit                 = km_AesExit,
    .min_keysize          = (128 / 8),
    .max_keysize          = (AES_MAX_KEY_SIZE / 8),
    .ivsize               = AES_BLOCK_SIZE,
    .setkey               = km_AesSetKey,
    .encrypt              = km_AesCbcEncrypt,
    .decrypt              = km_AesCbcDecrypt,
};

static struct aead_alg gcmAesAead = {
    .base.cra_name        = WOLFKM_GCM_NAME,
    .base.cra_driver_name = WOLFKM_GCM_DRIVER,
    .base.cra_priority    = WOLFKM_ALG_PRIORITY,
    .base.cra_blocksize   = AES_BLOCK_SIZE,
    .base.cra_ctxsize     = sizeof(struct km_AesCtx),
    .base.cra_module      = THIS_MODULE,
    .init                 = km_AesGcmInit,
    .exit                 = km_AesGcmExit,
    .setkey               = km_AesGcmSetKey,
    .setauthsize          = km_AesGcmSetAuthsize,
    .encrypt              = km_AesGcmEncrypt,
    .decrypt              = km_AesGcmDecrypt,
    .ivsize               = AES_BLOCK_SIZE,
    .maxauthsize          = AES_BLOCK_SIZE,
    .chunksize            = AES_BLOCK_SIZE,
};

static int linuxkm_register_alg(void)
{
    int ret = 0;

    ret =  crypto_register_skcipher(&cbcAesAlg);

    if (ret) {
        pr_err("crypto_register_skcipher failed with return code %d.\n", ret);
        return ret;
    }

    ret =  crypto_register_aead(&gcmAesAead);

    if (ret) {
        pr_err("crypto_register_aead failed with return code %d.\n", ret);
        return ret;
    }

    return 0;
}

static void linuxkm_unregister_alg(void)
{
    crypto_unregister_skcipher(&cbcAesAlg);
    crypto_unregister_aead(&gcmAesAead);
}

#ifdef LINUXKM_TEST_ALG
/* Given registered wolfcrypt kernel crypto, sanity test against
 * direct wolfcrypt calls. */

static int linuxkm_test_alg(void)
{
    struct crypto_skcipher *  tfm = NULL;
    struct skcipher_request * req = NULL;
    struct scatterlist        src, dst;
    int     ret = 1;
    Aes     aes;
    byte    key32[] =
    {
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66,
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66
    };
    byte    vector[] = /* Now is the time for all good men w/o trailing 0 */
    {
        0x4e,0x6f,0x77,0x20,0x69,0x73,0x20,0x74,
        0x68,0x65,0x20,0x74,0x69,0x6d,0x65,0x20,
        0x66,0x6f,0x72,0x20,0x61,0x6c,0x6c,0x20,
        0x67,0x6f,0x6f,0x64,0x20,0x6d,0x65,0x6e
    };
    byte    iv[]    = "1234567890abcdef";
    byte    enc[sizeof(vector)];
    byte    dec[sizeof(vector)];
    u8 *    enc2 = NULL;
    u8 *    dec2 = NULL;

    XMEMSET(enc, 0, sizeof(enc));
    XMEMSET(dec, 0, sizeof(enc));

    ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (ret) {
        pr_err("wolfcrypt wc_AesInit failed with return code %d.\n", ret);
        return -1;
    }

    ret = wc_AesSetKey(&aes, key32, AES_BLOCK_SIZE * 2, iv, AES_ENCRYPTION);
    if (ret) {
        pr_err("wolfcrypt wc_AesInit failed with return code %d\n", ret);
        return -1;
    }

    ret = wc_AesCbcEncrypt(&aes, enc, vector, sizeof(vector));
    if (ret) {
        pr_err("wolfcrypt wc_AesCbcEncrypt failed with return code %d\n", ret);
        return -1;
    }

    /* Re init for decrypt and set flag. */
    wc_AesFree(&aes);
    ret = wc_AesSetKey(&aes, key32, AES_BLOCK_SIZE * 2, iv, AES_DECRYPTION);
    if (ret) {
        pr_err("wolfcrypt wc_AesSetKey failed with return code %d.\n", ret);
        return -1;
    }

    ret = wc_AesCbcDecrypt(&aes, dec, enc, sizeof(vector));
    if (ret) {
        pr_err("wolfcrypt wc_AesCbcDecrypt failed with return code %d\n", ret);
        return -1;
    }

    ret = XMEMCMP(vector, dec, sizeof(vector));
    if (ret) {
        pr_err("error: vector and dec no not match: %d\n", ret);
        return -1;
    }

    /* now the kernel crypto part */
    enc2 = kmalloc(sizeof(vector), GFP_KERNEL);
    if (!enc2) {
        pr_err("error: kmalloc failed\n");
        goto test_alg_end;
    }

    dec2 = kmalloc(sizeof(vector), GFP_KERNEL);
    if (!dec2) {
        pr_err("error: kmalloc failed\n");
        goto test_alg_end;
    }

    memcpy(dec2, vector, sizeof(vector));

    tfm = crypto_alloc_skcipher(WOLFKM_CBC_DRIVER, 0, 0);

    if (IS_ERR(tfm)) {
        pr_err("error: allocating AES skcipher algorithm %s failed\n",
               WOLFKM_CBC_DRIVER);
        goto test_alg_end;
    }
    else {
        pr_info("info: allocate AES skcipher algorithm %s: good\n",
                WOLFKM_CBC_DRIVER);
    }

    ret = crypto_skcipher_setkey(tfm, key32, AES_BLOCK_SIZE * 2);

    if (ret) {
        pr_err("error: crypto_skcipher_setkey returned: %d\n", ret);
        goto test_alg_end;
    }
    else {
        pr_info("info: crypto_skcipher_setkey %s: good\n",
                WOLFKM_CBC_DRIVER);
    }

    req = skcipher_request_alloc(tfm, GFP_KERNEL);
    if (!req) {
        pr_err("error: allocating AES skcipher request %s failed\n",
               WOLFKM_CBC_DRIVER);
        goto test_alg_end;
    }
    else {
        pr_info("info: allocate AES skcipher request %s: good\n",
                WOLFKM_CBC_DRIVER);
    }

    sg_init_one(&src, dec2, sizeof(vector));
    sg_init_one(&dst, enc2, sizeof(vector));

    skcipher_request_set_crypt(req, &src, &dst, sizeof(vector), iv);

    ret = crypto_skcipher_encrypt(req);

    if (ret) {
        pr_err("error: crypto_skcipher_encrypt returned: %d\n", ret);
        goto test_alg_end;
    }
    else {
        pr_info("info: crypto_skcipher_encrypt %s: good\n",
                WOLFKM_CBC_DRIVER);
    }

    ret = XMEMCMP(enc, enc2, sizeof(vector));
    if (ret) {
        pr_err("error: enc and enc2 do not match: %d\n", ret);
    }
    else {
        pr_info("info: crypto api and wolfcrypt match: %s\n",
                WOLFKM_CBC_DRIVER);
    }

    memset(dec2, 0, sizeof(vector));
    sg_init_one(&src, enc2, sizeof(vector));
    sg_init_one(&dst, dec2, sizeof(vector));

    skcipher_request_set_crypt(req, &src, &dst, sizeof(vector), iv);

    ret = crypto_skcipher_decrypt(req);

    if (ret) {
        pr_err("error: crypto_skcipher_decrypt returned: %d\n", ret);
        goto test_alg_end;
    }
    else {
        pr_info("info: crypto_skcipher_decrypt %s: good\n",
                WOLFKM_CBC_DRIVER);
    }

    ret = XMEMCMP(dec, dec2, sizeof(vector));
    if (ret) {
        pr_err("error: dec and dec2 do not match: %d\n", ret);
    }
    else {
        pr_info("info: crypto api and wolfcrypt match: %s\n",
                WOLFKM_CBC_DRIVER);
    }

test_alg_end:

    if (enc2) { kfree(enc2); enc2 = NULL; }
    if (dec2) { kfree(dec2); dec2 = NULL; }
    if (req) { skcipher_request_free(req); req = NULL; }
    if (tfm) { crypto_free_skcipher(tfm); tfm = NULL; }

    return ret;
}
#endif
#endif /* LINUXKM_REGISTER_ALG */

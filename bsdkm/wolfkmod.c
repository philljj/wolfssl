/* freebsd system includes */
#include <sys/param.h> /* include first */
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/libkern.h> /* string functions. */
#include <sys/malloc.h>
#include <sys/systm.h> /* memset, memmove, printf, etc. */

/* wolf includes */
#include <wolfssl/wolfcrypt/libwolfssl_sources.h>

#ifdef WOLFCRYPT_ONLY
    #include <wolfssl/version.h>
#else
    #include <wolfssl/ssl.h>
#endif

#include <wolfssl/wolfcrypt/sha256.h>

static int
wolf_loader(struct module * m, int what, void * arg)
{
    switch (what) {
    case MOD_LOAD:
        printf("info: wolfkmod loaded\n");
        break;
    case MOD_UNLOAD:
        printf("info: wolfkmod unloaded\n");
        break;
    default:
        printf("info: wolfkmod: not implemented: %d\n", what);
        return EOPNOTSUPP;
    }

    (void)m;
    (void)arg;

    return 0;
}

static moduledata_t wolfmod = {
    "wolfkmod",  /* name */
    wolf_loader, /* loader */
    NULL          /* extra data */
};

DECLARE_MODULE(wolfkmod, wolfmod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);

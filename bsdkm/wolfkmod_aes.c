#if !defined(WC_SKIP_INCLUDED_C_FILES) && defined(BSDKM_CRYPTO_REGISTER)
#include <wolfssl/wolfcrypt/aes.h>

/*
 * cryptodev framework always uses a callback, even when sync.
 */
static int
wolfkdriv_test_crp_callback(struct cryptop * crp)
{
    (void)crp;
    return (0);
}

static int wolfkdriv_test_aes(int crid)
{
    crypto_session_t session = NULL;
    struct crypto_session_params csp;
    struct cryptop * crp = NULL;
    int    error = 0;
    uint8_t key[16] = {0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
                       0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01};

    memset(&csp, 0, sizeof(csp));

    /* gcm */
    csp.csp_cipher_alg = CRYPTO_AES_NIST_GCM_16;
    csp.csp_mode = CSP_MODE_AEAD;
    csp.csp_ivlen = AES_GCM_IV_LEN;
    csp.csp_cipher_key = key;
    csp.csp_cipher_klen = sizeof(key);

    error = crypto_newsession(&session, &csp, crid);

    if (error || session == NULL) {
        goto test_aes_out;
    }

    crp = crypto_getreq(session, M_WAITOK);

    crp->crp_callback = wolfkdriv_test_crp_callback;

    if (crp == NULL) {
        printf("error: wolfkdriv: test_aes: crypto_getreq failed\n");
        goto test_aes_out;
    }

    error = crypto_dispatch(crp);
test_aes_out:
    #if defined(WOLFSSL_BSDKM_VERBOSE_DEBUG)
    printf("info: wolfkdriv: test_aes: error=%d, session=%p, crp=%p\n",
           error, (void *)session, (void*)crp);
    #endif /* WOLFSSL_BSDKM_VERBOSE_DEBUG */

    if (crp != NULL) {
        crypto_freereq(crp);
        crp = NULL;
    }

    if (session != NULL) {
        crypto_freesession(session);
        session = NULL;
    }

    return (error);
}
#endif /* !WC_SKIP_INCLUDED_C_FILES && BSDKM_CRYPTO_REGISTER */

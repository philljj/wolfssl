#if !defined(WC_SKIP_INCLUDED_C_FILES) && defined(BSDKM_CRYPTO_REGISTER)
#include <wolfssl/wolfcrypt/aes.h>

#if defined(WOLFSSL_BSDKM_VERBOSE_DEBUG)
static void
wolfkmod_print_data(const char * what, const uint8_t * data, size_t data_len)
{
    size_t i = 0;

    printf("%s:\n", what);
    for (i = 0; i < data_len; ++i) {
        printf("0x%02x, ", data[i]);
        if ((i + 1) % 8 == 0) {
            printf("\n");
        }
    }

    printf("\n");
}
#endif /* WOLFSSL_BSDKM_VERBOSE_DEBUG */

/*
 * cryptodev framework always calls a callback, even when CRYPTOCAP_F_SYNC.
 */
static int
wolfkdriv_test_crp_callback(struct cryptop * crp)
{
    (void)crp;
    return (0);
}

/* Test aes-cbc encrypt and decrypt a small buffer with opencrypto
 * framework.
 */
static int wolfkdriv_test_aes_cbc(device_t dev, int crid)
{
    crypto_session_t session = NULL;
    struct crypto_session_params csp;
    struct cryptop * crp = NULL;
    int    error = 0;
    byte msg[] = {
        0x6e,0x6f,0x77,0x20,0x69,0x73,0x20,0x74,
        0x68,0x65,0x20,0x74,0x69,0x6d,0x65,0x20
    };
    const byte verify[] =
    {
        0x95,0x94,0x92,0x57,0x5f,0x42,0x81,0x53,
        0x2c,0xcc,0x9d,0x46,0x77,0xa2,0x33,0xcb
    };
    byte work[WC_AES_BLOCK_SIZE];
    /* padded to 16-bytes */
    const byte key[] = "0123456789abcdef   ";
    /* padded to 16-bytes */
    const byte iv[]  = "1234567890abcdef   ";

    memset(&csp, 0, sizeof(csp));
    memset(work, 0, sizeof(work));
    memcpy(work, msg, sizeof(msg));

    /* cbc */
    csp.csp_mode = CSP_MODE_CIPHER;
    csp.csp_cipher_alg = CRYPTO_AES_CBC;
    csp.csp_ivlen = WC_AES_BLOCK_SIZE;
    csp.csp_cipher_key = key;
    csp.csp_cipher_klen = WC_AES_BLOCK_SIZE;
    error = crypto_newsession(&session, &csp, crid);
    if (error || session == NULL) {
        goto test_aes_cbc_out;
    }

    crp = crypto_getreq(session, M_WAITOK);
    if (crp == NULL) {
        device_printf(dev, "error: test_aes: crypto_getreq failed\n");
        goto test_aes_cbc_out;
    }

    crp->crp_callback = wolfkdriv_test_crp_callback;
    crp->crp_op = CRYPTO_OP_ENCRYPT;
    crp->crp_flags = CRYPTO_F_IV_SEPARATE;

    memcpy(crp->crp_iv, iv, WC_AES_BLOCK_SIZE);

    crypto_use_buf(crp, work, sizeof(work));
    crp->crp_payload_start = 0;
    crp->crp_payload_length = sizeof(work);

    error = crypto_dispatch(crp);
    if (error) {
        goto test_aes_cbc_out;
    }

    error = XMEMCMP(work, verify, sizeof(verify));
    if (error) {
        goto test_aes_cbc_out;
    }

    wolfkmod_print_data("msg_enc", work, sizeof(work));

    crp->crp_op = CRYPTO_OP_DECRYPT;

    error = crypto_dispatch(crp);
    if (error) {
        goto test_aes_cbc_out;
    }

    error = XMEMCMP(work, msg, sizeof(msg));
    if (error) {
        goto test_aes_cbc_out;
    }

    wolfkmod_print_data("msg_dec", work, sizeof(work));

test_aes_cbc_out:
    #if defined(WOLFSSL_BSDKM_VERBOSE_DEBUG)
    device_printf(dev, "info: test_aes_cbc: error=%d, session=%p, crp=%p\n",
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

/* Encrypt a buffer larger than aes block size.
 * Verify direct wolfcrypt API and opencrypto framework return
 * same result.
 */
static int wolfkdriv_test_aes_cbc_big(device_t dev, int crid)
{
    crypto_session_t session = NULL;
    struct crypto_session_params csp;
    struct cryptop * crp = NULL;
    Aes *            aes_encrypt = NULL;
    int    error = 0;
    byte msg[] = {
        0x6e,0x6f,0x77,0x20,0x69,0x73,0x20,0x74,
        0x68,0x65,0x20,0x74,0x69,0x6d,0x65,0x20,
        0x6e,0x6f,0x77,0x20,0x69,0x73,0x20,0x74,
        0x68,0x65,0x20,0x74,0x69,0x6d,0x65,0x20,
        0x6e,0x6f,0x77,0x20,0x69,0x73,0x20,0x74,
        0x68,0x65,0x20,0x74,0x69,0x6d,0x65,0x20
    };
    byte work1[WC_AES_BLOCK_SIZE * 3]; /* wolfcrypt buffer */
    byte work2[WC_AES_BLOCK_SIZE * 3]; /* opencrypto buffer */
    /* padded to 16-bytes */
    const byte key[] = "0123456789abcdef   ";
    /* padded to 16-bytes */
    const byte iv[]  = "1234567890abcdef   ";

    memset(&csp, 0, sizeof(csp));
    memcpy(work1, msg, sizeof(msg)); /* wolfcrypt work buffer */
    memcpy(work2, msg, sizeof(msg)); /* opencrypto work buffer */

    /* wolfcrypt encrypt */
    aes_encrypt = (Aes *)XMALLOC(sizeof(Aes), NULL,
                                          DYNAMIC_TYPE_AES);
    if (aes_encrypt == NULL) {
        error = ENOMEM;
        device_printf(dev, "error: malloc failed\n");
        goto test_aes_cbc_big_out;
    }

    error = wc_AesInit(aes_encrypt, NULL, INVALID_DEVID);
    if (error) {
        device_printf(dev, "error: newsession_cipher: aes init: %d\n", error);
        goto test_aes_cbc_big_out;
    }

    error = wc_AesSetKey(aes_encrypt, key, 16, iv, AES_ENCRYPTION);
    if (error) {
        device_printf(dev, "error: wc_AesSetKey: %d\n", error);
        goto test_aes_cbc_big_out;
    }

    error = wc_AesCbcEncrypt(aes_encrypt, work1, work1, sizeof(work1));
    if (error) {
        device_printf(dev, "error: wc_AesCbcEncrypt: %d\n", error);
        goto test_aes_cbc_big_out;
    }

    /* opencrypto encrypt */
    csp.csp_mode = CSP_MODE_CIPHER;
    csp.csp_cipher_alg = CRYPTO_AES_CBC;
    csp.csp_ivlen = WC_AES_BLOCK_SIZE;
    csp.csp_cipher_key = key;
    csp.csp_cipher_klen = WC_AES_BLOCK_SIZE;
    error = crypto_newsession(&session, &csp, crid);
    if (error || session == NULL) {
        goto test_aes_cbc_big_out;
    }

    crp = crypto_getreq(session, M_WAITOK);
    if (crp == NULL) {
        device_printf(dev, "error: test_aes: crypto_getreq failed\n");
        goto test_aes_cbc_big_out;
    }

    crp->crp_callback = wolfkdriv_test_crp_callback;
    crp->crp_op = CRYPTO_OP_ENCRYPT;
    crp->crp_flags = CRYPTO_F_IV_SEPARATE;

    memcpy(crp->crp_iv, iv, WC_AES_BLOCK_SIZE);

    crypto_use_buf(crp, work2, sizeof(work2));
    crp->crp_payload_start = 0;
    crp->crp_payload_length = sizeof(work2);

    error = crypto_dispatch(crp);
    if (error) {
        goto test_aes_cbc_big_out;
    }

    error = XMEMCMP(work1, work2, sizeof(work2));
    if (error) {
        goto test_aes_cbc_big_out;
    }

    wolfkmod_print_data("msg_enc", work2, sizeof(work2));

    /* opencrypto decrypt */
    crp->crp_op = CRYPTO_OP_DECRYPT;

    error = crypto_dispatch(crp);
    if (error) {
        goto test_aes_cbc_big_out;
    }

    error = XMEMCMP(work2, msg, sizeof(msg));
    if (error) {
        goto test_aes_cbc_big_out;
    }

    wolfkmod_print_data("msg_dec", work2, sizeof(work2));

test_aes_cbc_big_out:
    #if defined(WOLFSSL_BSDKM_VERBOSE_DEBUG)
    device_printf(dev, "info: test_aes_cbc_big: error=%d, session=%p, crp=%p\n",
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

    if (aes_encrypt != NULL) {
        wc_AesFree(aes_encrypt);
        XFREE(aes_encrypt, NULL, DYNAMIC_TYPE_AES);
        aes_encrypt = NULL;
    }

    return (error);
}

static int wolfkdriv_test_aes(device_t dev, int crid)
{
    int error = 0;

    if (error == 0) {
        error = wolfkdriv_test_aes_cbc(dev, crid);
    }

    if (error == 0) {
        error = wolfkdriv_test_aes_cbc_big(dev, crid);
    }

    /*
    if (error == 0) {
        error = wolfkdriv_test_aes_gcm(dev, crid);
    }
    */

    return (error);
}
#endif /* !WC_SKIP_INCLUDED_C_FILES && BSDKM_CRYPTO_REGISTER */

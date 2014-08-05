#include "encrypt.h"

//#define DEBUG

//For OPENSSL
#include <openssl/md5.h>
#include <openssl/rand.h>
//END OPENSSL

#define OFFSET_ROL(p, o) ((uint64_t)(*(p + o)) << (8 * o))

#ifdef DEBUG
#include <iostream>
#include <string>
static void dump(char *tag, char *text, int len)
{
    int i;
    printf("%s: ", tag);
    for (i = 0; i < len; i++)
    {
        printf("0x%02x ", (uint8_t)text[i]);
    }
    printf("\n");
}
#endif

static const char* supported_ciphers[CIPHER_NUM] =
{
    "table",
    "rc4",
    "aes-128-cfb",
    "aes-192-cfb",
    "aes-256-cfb",
    "bf-cfb",
    "camellia-128-cfb",
    "camellia-192-cfb",
    "camellia-256-cfb",
    "cast5-cfb",
    "des-cfb",
    "idea-cfb",
    "rc2-cfb",
    "seed-cfb"
};

encrypt::encrypt(QString pass, QString method, QObject *parent) :
    QObject(parent)
{
    enc_table = NULL;
    dec_table = NULL;
    method_crypt = enc_init(pass, method);
}

encrypt::~encrypt()
{
    if(enc_table)
        free (enc_table);

    if(dec_table)
        free (dec_table);
}

void encrypt::init_ctx(struct enc_ctx *ctx, bool encode)
{
    if (method_crypt)
    {
//        enc_ctx_init(method_crypt, e_ctx, 1);
//        enc_ctx_init(method_crypt, d_ctx, 0);
        enc_ctx_init(method_crypt, ctx, encode?1:0);
    }
}

static int random_compare(const void *_x, const void *_y, uint32_t i, uint64_t a)
{
    uint8_t x = *((uint8_t *) _x);
    uint8_t y = *((uint8_t*) _y);
    return (a % (x + i) - a % (y + i));
}

static void merge(uint8_t *left, int llength, uint8_t *right,
                  int rlength, uint32_t salt, uint64_t key)
{
    uint8_t *ltmp = (uint8_t *) malloc(llength * sizeof(uint8_t));
    uint8_t *rtmp = (uint8_t *) malloc(rlength * sizeof(uint8_t));

    uint8_t *ll = ltmp;
    uint8_t *rr = rtmp;

    uint8_t *result = left;

    memcpy(ltmp, left, llength * sizeof(uint8_t));
    memcpy(rtmp, right, rlength * sizeof(uint8_t));

    while (llength > 0 && rlength > 0)
    {
        if (random_compare(ll, rr, salt, key) <= 0)
        {
            *result = *ll;
            ++ll;
            --llength;
        }
        else
        {
            *result = *rr;
            ++rr;
            --rlength;
        }
        ++result;
    }

    if (llength > 0)
        while (llength > 0)
        {
            *result = *ll;
            ++result;
            ++ll;
            --llength;
        }
    else
        while (rlength > 0)
        {
            *result = *rr;
            ++result;
            ++rr;
            --rlength;
        }

    free(ltmp);
    free(rtmp);
}

static void merge_sort(uint8_t array[], int length,
                       uint32_t salt, uint64_t key)
{
    uint8_t middle;
    uint8_t *left, *right;
    int llength;

    if (length <= 1)
        return;

    middle = length / 2;

    llength = length - middle;

    left = array;
    right = array + llength;

    merge_sort(left, llength, salt, key);
    merge_sort(right, middle, salt, key);
    merge(left, llength, right, middle, salt, key);
}

int encrypt::enc_get_iv_len()
{
    return enc_iv_len;
}

unsigned char * encrypt::enc_md5(const unsigned char *d, size_t n, unsigned char *md)
{
#if defined(USE_CRYPTO_OPENSSL)
    return MD5(d, n, md);
#elif defined(USE_CRYPTO_POLARSSL)
    static unsigned char m[16];
    if (md == NULL)
    {
        md = m;
    }
    md5(d, n, md);
    return md;
#endif
}

void encrypt::enc_table_init(const char *pass)
{
    uint32_t i;
    uint32_t salt;
    uint64_t key = 0;
    uint8_t *digest;

    enc_table = (uint8_t *)malloc(256);
    dec_table = (uint8_t *)malloc(256);
    memset(enc_table, 0, 256);
    memset(dec_table, 0, 256);

    digest = enc_md5((const uint8_t *) pass, strlen(pass), NULL);
#ifdef DEBUG
    dump("enc_md5", (char *)digest, sizeof(digest));
    printf("pass:%s\nlength:%d", pass, strlen(pass));
#endif

    for (i = 0; i < 8; i++)
    {
        key += OFFSET_ROL(digest, i);
    }

    for(i = 0; i < 256; ++i)
    {
        enc_table[i] = i;
    }
    for(i = 1; i < 1024; ++i)
    {
        salt = i;
        merge_sort(enc_table, 256, salt, key);
    }
    for(i = 0; i < 256; ++i)
    {
        // gen decrypt table from encrypt table
        dec_table[enc_table[i]] = i;
    }
#ifdef DEBUG
    dump("enc_table", (char *)enc_table, 256);
    dump("dec_table", (char *)dec_table, 256);
#endif
}

int encrypt::cipher_iv_size(const cipher_kt_t *cipher)
{
#if defined(USE_CRYPTO_OPENSSL)
    return EVP_CIPHER_iv_length (cipher);
#elif defined(USE_CRYPTO_POLARSSL)
    if (cipher == NULL)
    {
        return 0;
    }
    return cipher->iv_size;
#endif
}

int encrypt::cipher_key_size (const cipher_kt_t *cipher)
{
#if defined(USE_CRYPTO_OPENSSL)
    return EVP_CIPHER_key_length(cipher);
#elif defined(USE_CRYPTO_POLARSSL)
    if (cipher == NULL)
    {
        return 0;
    }
    /* Override PolarSSL 32 bit default key size with sane 128 bit default */
    if (cipher->base != NULL && POLARSSL_CIPHER_ID_BLOWFISH == cipher->base->cipher)
    {
        return 128 / 8;
    }
    return cipher->key_length / 8;
#endif
}

int encrypt::bytes_to_key(const cipher_kt_t *cipher, const digest_type_t *md, const uint8_t *pass, uint8_t *key, uint8_t *iv)
{
    size_t datal;
    datal = strlen((const char *) pass);
#if defined(USE_CRYPTO_OPENSSL)
    return EVP_BytesToKey(cipher, md, NULL, pass, datal, 1, key, iv);
#elif defined(USE_CRYPTO_POLARSSL)
    md_context_t c;
    unsigned char md_buf[MAX_MD_SIZE];
    int niv;
    int nkey;
    int addmd;
    unsigned int mds;
    unsigned int i;
    int rv;

    nkey = cipher_key_size(cipher);
    niv = cipher_iv_size(cipher);
    rv = nkey;
    if (pass == NULL)
    {
        return nkey;
    }

    memset(&c, 0, sizeof(md_context_t));
    if (md_init_ctx(&c, md))
    {
        return 0;
    }
    addmd = 0;
    mds = md_get_size(md);
    for (;;)
    {
        int error;
        do
        {
            error = 1;
            if (md_starts(&c))
            {
                break;
            }
            if (addmd)
            {
                if (md_update(&c, &(md_buf[0]), mds))
                {
                    break;
                }
            }
            else
            {
                addmd = 1;
            }
            if (md_update(&c, pass, datal))
                break;
            if (md_finish(&c, &(md_buf[0])))
                break;
            error = 0;
        }
        while (0);
        if (error)
        {
            md_free_ctx(&c);
            memset(md_buf, 0, MAX_MD_SIZE);
            return 0;
        }

        i=0;
        if (nkey)
        {
            for (;;)
            {
                if (nkey == 0) break;
                if (i == mds) break;
                if (key != NULL)
                    *(key++)=md_buf[i];
                nkey--;
                i++;
            }
        }
        if (niv && (i != mds))
        {
            for (;;)
            {
                if (niv == 0) break;
                if (i == mds) break;
                if (iv != NULL)
                    *(iv++)=md_buf[i];
                niv--;
                i++;
            }
        }
        if ((nkey == 0) && (niv == 0)) break;
    }
    md_free_ctx(&c);
    memset(md_buf, 0, MAX_MD_SIZE);
    return rv;
#endif
}

int encrypt::rand_bytes(uint8_t *output, int len)
{
#if defined(USE_CRYPTO_OPENSSL)
    return RAND_bytes(output, len);
#elif defined(USE_CRYPTO_POLARSSL)
    static entropy_context ec = {};
    static ctr_drbg_context cd_ctx = {};
    static unsigned char rand_initialised = 0;
    const size_t blen = min(len, CTR_DRBG_MAX_REQUEST);

    if (!rand_initialised)
    {
#ifdef _WIN32
        HCRYPTPROV hProvider;
        union
        {
            unsigned __int64 seed;
            BYTE buffer[8];
        } rand_buffer;

        hProvider = 0;
        if (CryptAcquireContext(&hProvider, 0, 0, PROV_RSA_FULL, \
                                CRYPT_VERIFYCONTEXT | CRYPT_SILENT))
        {
            CryptGenRandom(hProvider, 8, rand_buffer.buffer);
            CryptReleaseContext(hProvider, 0);
        }
        else
        {
            rand_buffer.seed = (unsigned __int64) clock();
        }
#else
        FILE *urand;
        union
        {
            uint64_t seed;
            uint8_t buffer[8];
        } rand_buffer;

        urand = fopen("/dev/urandom", "r");
        if (urand)
        {
            fread(&rand_buffer.seed, sizeof(rand_buffer.seed), 1, urand);
            fclose(urand);
        }
        else
        {
            rand_buffer.seed = (uint64_t) clock();
        }
#endif
        entropy_init(&ec);
        if (ctr_drbg_init(&cd_ctx, entropy_func, &ec, (const unsigned char *) rand_buffer.buffer, 8) != 0)
        {
#if POLARSSL_VERSION_NUMBER >= 0x01030000
            entropy_free(&ec);
#endif
            qFatal("Failed to initialize random generator");
        }
        rand_initialised = 1;
    }
    while (len > 0)
    {
        if (ctr_drbg_random(&cd_ctx, output, blen) != 0)
        {
            return 0;
        }
        output += blen;
        len -= blen;
    }
    return 1;
#endif
}

const cipher_kt_t *get_cipher_type(int method)
{
    if (method <= TABLE || method >= CIPHER_NUM)
    {
        qCritical("get_cipher_type(): Illegal method");
        return NULL;
    }

    const char *ciphername = supported_ciphers[method];
#if defined(USE_CRYPTO_OPENSSL)
    return EVP_get_cipherbyname(ciphername);
#elif defined(USE_CRYPTO_POLARSSL)
    const char *polarname = supported_ciphers_polarssl[method];
    if (strcmp(polarname, CIPHER_UNSUPPORTED) == 0)
    {
        qCritical("Cipher %s currently is not supported by PolarSSL library", ciphername);
        return NULL;
    }
    return cipher_info_from_string(polarname);
#endif
}

const digest_type_t *get_digest_type(const char *digest)
{
    if (digest == NULL)
    {
        qCritical("get_digest_type(): Digest name is null");
        return NULL;
    }

#if defined(USE_CRYPTO_OPENSSL)
    return EVP_get_digestbyname(digest);
#elif defined(USE_CRYPTO_POLARSSL)
    return md_info_from_string(digest);
#endif
}

void encrypt::cipher_context_init(cipher_ctx_t *ctx, int method, int enc)
{
    if (method <= TABLE || method >= CIPHER_NUM)
    {
        qCritical("cipher_context_init(): Illegal method");
        return;
    }

    const char *ciphername = supported_ciphers[method];
#if defined(USE_CRYPTO_APPLECC)
    cipher_cc_t *cc = &ctx->cc;
    cc->cryptor = NULL;
    cc->cipher = supported_ciphers_applecc[method];
    if (cc->cipher == kCCAlgorithmInvalid)
    {
        cc->valid = kCCContextInvalid;
    }
    else
    {
        cc->valid = kCCContextValid;
        if (cc->cipher == kCCAlgorithmRC4)
        {
            cc->mode = kCCModeRC4;
            cc->padding = ccNoPadding;
        }
        else
        {
            cc->mode = kCCModeCFB;
            cc->padding = ccPKCS7Padding;
        }
        return;
    }
#endif

    cipher_evp_t *evp = &ctx->evp;
    const cipher_kt_t *cipher = get_cipher_type(method);
#if defined(USE_CRYPTO_OPENSSL)
    if (cipher == NULL)
    {
        qCritical("Cipher %s not found in OpenSSL library", ciphername);
        qFatal("Cannot initialize cipher");
    }
    EVP_CIPHER_CTX_init(evp);
    if (!EVP_CipherInit_ex(evp, cipher, NULL, NULL, NULL, enc))
    {
        qCritical("Cannot initialize cipher %s", ciphername);
        exit(EXIT_FAILURE);
    }
    if (!EVP_CIPHER_CTX_set_key_length(evp, enc_key_len))
    {
        EVP_CIPHER_CTX_cleanup(evp);
        qCritical("Invalid key length: %d", enc_key_len);
        exit(EXIT_FAILURE);
    }
    if (method > RC4)
    {
        EVP_CIPHER_CTX_set_padding(evp, 1);
    }
#elif defined(USE_CRYPTO_POLARSSL)
    if (cipher == NULL)
    {
        qCritical("Cipher %s not found in PolarSSL library", ciphername);
        qFatal("Cannot initialize PolarSSL cipher");
    }
    if (cipher_init_ctx(evp, cipher) != 0)
    {
        qFatal("Cannot initialize PolarSSL cipher context");
    }
#endif
}

void encrypt::cipher_context_set_iv(cipher_ctx_t *ctx, uint8_t *iv, size_t iv_len, int enc)
{
    if (iv == NULL)
    {
        qCritical("cipher_context_set_iv(): IV is null");
        return;
    }
    if (enc)
    {
        rand_bytes(iv, iv_len);
    }

#ifdef USE_CRYPTO_APPLECC
    cipher_cc_t *cc = &ctx->cc;
    if (cc->valid == kCCContextValid)
    {
        memcpy(cc->iv, iv, iv_len);
        memcpy(cc->key, enc_key, enc_key_len);
        cc->iv_len = iv_len;
        cc->key_len = enc_key_len;
        cc->encrypt = enc ? kCCEncrypt : kCCDecrypt;
        if (cc->cryptor != NULL)
        {
            CCCryptorRelease(cc->cryptor);
            cc->cryptor = NULL;
        }

        CCCryptorStatus ret;
        ret = CCCryptorCreateWithMode(
                  cc->encrypt,
                  cc->mode,
                  cc->cipher,
                  cc->padding,
                  cc->iv, cc->key, cc->key_len,
                  NULL, 0, 0, 0,
                  &cc->cryptor);
        if (ret != kCCSuccess)
        {
            if (cc->cryptor != NULL)
            {
                CCCryptorRelease(cc->cryptor);
                cc->cryptor = NULL;
            }
            qFatal("Cannot set CommonCrypto key and IV");
        }
        return;
    }
#endif

    cipher_evp_t *evp = &ctx->evp;
    if (evp == NULL)
    {
        qCritical("cipher_context_set_iv(): Cipher context is null");
        return;
    }
#if defined(USE_CRYPTO_OPENSSL)
    if (!EVP_CipherInit_ex(evp, NULL, NULL, enc_key, iv, enc))
    {
        EVP_CIPHER_CTX_cleanup(evp);
        qFatal("Cannot set key and IV");
    }
#elif defined(USE_CRYPTO_POLARSSL)
    if (cipher_setkey(evp, enc_key, enc_key_len * 8, enc) != 0)
    {
        cipher_free_ctx(evp);
        qFatal("Cannot set PolarSSL cipher key");
    }
#if POLARSSL_VERSION_NUMBER >= 0x01030000
    if (cipher_set_iv(evp, iv, iv_len) != 0)
    {
        cipher_free_ctx(evp);
        qFatal("Cannot set PolarSSL cipher IV");
    }
    if(cipher_reset(evp) != 0)
    {
        cipher_free_ctx(evp);
        qFatal("Cannot finalize PolarSSL cipher context");
    }
#else
    if(cipher_reset(evp, iv) != 0)
    {
        cipher_free_ctx(evp);
        qFatal("Cannot set PolarSSL cipher IV");
    }
#endif
#endif

#ifdef DEBUG
    dump("IV", (char *) iv, iv_len);
#endif
}

void encrypt::cipher_context_release(cipher_ctx_t *ctx)
{
#ifdef USE_CRYPTO_APPLECC
    cipher_cc_t *cc = &ctx->cc;
    if (cc->cryptor != NULL)
    {
        CCCryptorRelease(cc->cryptor);
        cc->cryptor = NULL;
    }
    if (cc->valid == kCCContextValid)
    {
        return;
    }
#endif

    cipher_evp_t *evp = &ctx->evp;
#if defined(USE_CRYPTO_OPENSSL)
    EVP_CIPHER_CTX_cleanup(evp);
#elif defined(USE_CRYPTO_POLARSSL)
    cipher_free_ctx(evp);
#endif
}

static int cipher_context_update(cipher_ctx_t *ctx, uint8_t *output, int *olen,
                                 const uint8_t *input, int ilen)
{
#ifdef USE_CRYPTO_APPLECC
    cipher_cc_t *cc = &ctx->cc;
    if (cc->valid == kCCContextValid)
    {
        CCCryptorStatus ret;
        ret = CCCryptorUpdate(cc->cryptor, input, ilen, output, ilen + BLOCK_SIZE, (size_t *) olen);
        return (ret == kCCSuccess) ? 1 : 0;
    }
#endif
    cipher_evp_t *evp = &ctx->evp;
#if defined(USE_CRYPTO_OPENSSL)
    return EVP_CipherUpdate(evp, (uint8_t *) output, olen,
                            (const uint8_t *) input, (size_t) ilen);
#elif defined(USE_CRYPTO_POLARSSL)
    return !cipher_update(evp, (const uint8_t *) input, (size_t) ilen,
                          (uint8_t *) output, (size_t *) olen);
#endif
}

char* encrypt::ss_encrypt_all(int buf_size, char *plaintext, ssize_t *len, int method)
{
    if (method > TABLE)
    {
        cipher_ctx_t evp;
        cipher_context_init(&evp, method, 1);

        int c_len = *len + BLOCK_SIZE;
        int iv_len = enc_iv_len;
        int err = 0;
        char *ciphertext = (char *)malloc(max(iv_len + c_len, buf_size));

        uint8_t iv[MAX_IV_LENGTH];
        cipher_context_set_iv(&evp, iv, iv_len, 1);
        memcpy(ciphertext, iv, iv_len);

        err = cipher_context_update(&evp, (uint8_t*)(ciphertext+iv_len),
                                    &c_len, (const uint8_t *)plaintext, *len);

        if (!err)
        {
            free(ciphertext);
            free(plaintext);
            cipher_context_release(&evp);
            return NULL;
        }

#ifdef DEBUG
        dump("PLAIN", plaintext, *len);
        dump("CIPHER", ciphertext + iv_len, c_len);
#endif

        *len = iv_len + c_len;
        free(plaintext);
        cipher_context_release(&evp);

        return ciphertext;

    }
    else
    {
        char *begin = plaintext;
        while (plaintext < begin + *len)
        {
            *plaintext = (char)enc_table[(uint8_t)*plaintext];
            plaintext++;
        }
        return begin;
    }
}

QByteArray* encrypt::ss_encrypt(int buf_size, QByteArray *out, QByteArray *in, ssize_t *len, struct enc_ctx *ctx)
{
    if (TABLE != method_crypt)
    {
        int c_len = *len + BLOCK_SIZE;
        int iv_len = 0;
        int err = 0;
        out->resize(max(iv_len + c_len, buf_size));
        //char *ciphertext = (char *)malloc(max(iv_len + c_len, buf_size));
        char *ciphertext = out->data();
        char *plaintext = in->data();

        if (!ctx->init)
        {
            uint8_t iv[MAX_IV_LENGTH];
            iv_len = enc_iv_len;
            cipher_context_set_iv(&ctx->evp, iv, iv_len, 1);
            memcpy(ciphertext, iv, iv_len);
            ctx->init = 1;
        }

        err = cipher_context_update(&ctx->evp, (uint8_t*)(ciphertext+iv_len),
                                    &c_len, (const uint8_t *)plaintext, *len);
        if (!err)
        {
            return NULL;
        }

#ifdef DEBUG
        dump("PLAIN", plaintext, *len);
        dump("CIPHER", ciphertext + iv_len, c_len);
#endif

        *len = iv_len + c_len;
        return out;
    }
    else
    {
        char *plaintext = in->data();
        char *begin = plaintext;
        while (plaintext < begin + *len)
        {
            *plaintext = (char)enc_table[(uint8_t)*plaintext];
            plaintext++;
        }
        return in;
    }
}

char* encrypt::ss_decrypt_all(int buf_size, char *ciphertext, ssize_t *len, int method)
{
    if (method > TABLE)
    {
        cipher_ctx_t evp;
        cipher_context_init(&evp, method, 0);

        int p_len = *len + BLOCK_SIZE;
        int iv_len = enc_iv_len;
        int err = 0;
        char *plaintext = (char *)malloc(max(p_len, buf_size));

        uint8_t iv[MAX_IV_LENGTH];
        memcpy(iv, ciphertext, iv_len);
        cipher_context_set_iv(&evp, iv, iv_len, 0);

        err = cipher_context_update(&evp, (uint8_t*)plaintext, &p_len,
                                    (const uint8_t*)(ciphertext + iv_len), *len - iv_len);
        if (!err)
        {
            free(ciphertext);
            free(plaintext);
            cipher_context_release(&evp);
            return NULL;
        }

#ifdef DEBUG
        dump("PLAIN", plaintext, p_len);
        dump("CIPHER", ciphertext + iv_len, *len - iv_len);
#endif

        *len = p_len;
        free(ciphertext);
        cipher_context_release(&evp);
        return plaintext;
    }
    else
    {
        char *begin = ciphertext;
        while (ciphertext < begin + *len)
        {
            *ciphertext = (char)dec_table[(uint8_t)*ciphertext];
            ciphertext++;
        }
        return begin;
    }
}

QByteArray* encrypt::ss_decrypt(int buf_size, QByteArray *out, QByteArray *in, ssize_t *len, struct enc_ctx *ctx)
{
    if (TABLE != method_crypt)
    {
        int p_len = *len + BLOCK_SIZE;
        int iv_len = 0;
        int err = 0;
        out->resize(max(p_len, buf_size));
        char *plaintext = out->data();
        char *ciphertext = in->data();
        //char *plaintext = (char *)malloc(max(p_len, buf_size));

        if (!ctx->init)
        {
            uint8_t iv[MAX_IV_LENGTH];
            iv_len = enc_iv_len;
            memcpy(iv, ciphertext, iv_len);
            cipher_context_set_iv(&ctx->evp, iv, iv_len, 0);
            ctx->init = 1;
        }

        err = cipher_context_update(&ctx->evp, (uint8_t*)plaintext, &p_len,
                                    (const uint8_t*)(ciphertext + iv_len), *len - iv_len);

        if (!err)
        {
            return NULL;
        }

#ifdef DEBUG
        dump("PLAIN", plaintext, p_len);
        dump("CIPHER", ciphertext + iv_len, *len - iv_len);
#endif

        *len = p_len;
        return out;
    }
    else
    {
        char *begin = in->data();
        char *ciphertext = begin;
        while (ciphertext < begin + *len)
        {
            *ciphertext = (char)dec_table[(uint8_t)*ciphertext];
            ciphertext++;
        }
        return in;
    }
}

void encrypt::enc_ctx_init(int method, struct enc_ctx *ctx, int enc)
{
    memset(ctx, 0, sizeof(struct enc_ctx));
    cipher_context_init(&ctx->evp, method, enc);
#ifdef DEBUG
    dump((char *)"coder method:", (char *)&method, sizeof(int));
    dump(enc?(char *)"1enc":(char *)"0enc", (char *)ctx, sizeof(struct enc_ctx));
#endif
}

void encrypt::enc_key_init(int method, const char *pass)
{
    if (method <= TABLE || method >= CIPHER_NUM)
    {
        qCritical("enc_key_init(): Illegal method");
        return;
    }

#if defined(USE_CRYPTO_OPENSSL)
    OpenSSL_add_all_algorithms();
#endif

#if defined(USE_CRYPTO_POLARSSL) && defined(USE_CRYPTO_APPLECC)
    cipher_kt_t cipher_info;
#endif

    uint8_t iv[MAX_IV_LENGTH];
    const cipher_kt_t *cipher = get_cipher_type(method);
    if (cipher == NULL)
    {
        do
        {
#if defined(USE_CRYPTO_POLARSSL) && defined(USE_CRYPTO_APPLECC)
            if (supported_ciphers_applecc[method] != kCCAlgorithmInvalid)
            {
                cipher_info.base = NULL;
                cipher_info.key_length = supported_ciphers_key_size[method] * 8;
                cipher_info.iv_size = supported_ciphers_iv_size[method];
                cipher = (const cipher_kt_t *) &cipher_info;
                break;
            }
#endif
            qCritical("Cipher %s not found in crypto library", supported_ciphers[method]);
            qFatal("Cannot initialize cipher");
        }
        while (0);
    }
    const digest_type_t *md = get_digest_type("MD5");
    if (md == NULL)
    {
        qFatal("MD5 Digest not found in crypto library");
    }

    enc_key_len = bytes_to_key(cipher, md, (const uint8_t *) pass, enc_key, iv);
    if (enc_key_len == 0)
    {
        qFatal("Cannot generate key and IV");
    }
    enc_iv_len = cipher_iv_size(cipher);
#ifdef DEBUG
    printf("enc_key_len:%d\n", enc_iv_len);
    dump("enc_key", (char *)enc_key, sizeof(enc_key));
#endif
}

#ifdef testmd5
/**
* @brief 十六进制转二进制
* @author
*/
inline std::string Hex2Bin(std::string _in)
{
    long int binSize = 0;
    unsigned char *t = NULL;
    std::string result;

    t = string_to_hex((char *)_in.c_str(), &binSize);  // 位于 x509v3.h

    result.clear();
    result.append((char *)t, binSize);

    return result;
}
inline std::string Bin2Hex(std::string _in)
{
    std::string result;
    const char hexdig[] = "0123456789ABCDEF";

    if(_in.empty())
    {
        return result;
    }

    result.clear();
    for(std::string::iterator i = _in.begin(); i != _in.end(); i++)
    {
        result.append(1, hexdig[(*i >> 4) & 0xf]);  //留下高四位
        result.append(1, hexdig[(*i & 0xf)]);  //留下低四位

    }

    return result;
}
inline std::string My_MD5(std::string msg)
{
    std::string result;
    if(msg.empty())
    {
        return result;
    }

    const int digestLen = 16;
    unsigned char digest[digestLen] = {0};
    memset(digest, 0x00, sizeof(digest));

    MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx, msg.c_str(), msg.size());
    MD5_Final(digest, &ctx);

    result.clear();
    result.append((char *)digest, digestLen);

    return Bin2Hex(result);
}

/**
* @brief MD5 校验
* @author
* @param digest 十六进制字符串形式摘要
* @return true 校验成功
* @return false 校验失败
*
*/
inline bool My_MD5_Verify(std::string _msg, std::string _digest)
{
    std::string t = My_MD5(_msg);

    // 强制转大写，忽略大小写差异
    for(std::string::iterator iter = _digest.begin();
            iter != _digest.end();
                iter++)
    {
        if(isalpha(*iter))
        {
            *iter = toupper(*iter);
        }
    }

    if(0 == t.compare(_digest))
    {
        return true;
    }
    else
    {
        return false;
    }
}
int test()
{
    std::string msg("I'am test message!!!");
    std::string digest = My_MD5(msg);
    std::cout << "Digest:" << digest << std::endl;

    std::string expectDigest("07B12819CB3AA62F9B45072B414B0512");
    if(!expectDigest.compare(My_MD5(msg)))
    {
        std::cout << "MD5 Verify Success!!" << std::endl;
    }
    else
    {
        std::cout << "MD5 Verify Fail!!" << std::endl;
    }

    return 0;
}
#endif

int encrypt::enc_init(QString pass, QString method)
{
    int m = TABLE;
    QByteArray passbuf = pass.toLatin1();
    if (!method.isEmpty())
    {
        for (m = TABLE; m < CIPHER_NUM; m++)
        {
            if ( method.compare(supported_ciphers[m],  Qt::CaseInsensitive) == 0)
            {
                qDebug() << "find enc table:" << supported_ciphers[m];
                break;
            }
        }
        if (m >= CIPHER_NUM)
        {
            qCritical("Invalid cipher name: %s, use table instead", method.toLatin1().data());
            m = TABLE;
        }
    }
    if (m == TABLE)
    {
        enc_table_init(passbuf.data());
    }
    else
    {
        enc_key_init(m, passbuf.data());
    }

    return m;
}

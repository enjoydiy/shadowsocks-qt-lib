#ifndef ENCRYPT_H
#define ENCRYPT_H

#include <QObject>
#include <QString>
#include "base.h"

//C++ STD HEAD
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#ifdef max
    #undef max
#endif

#ifdef min
    #undef min
#endif

//OPENSSL releated
#include "openssl/evp.h"
typedef EVP_CIPHER cipher_kt_t;
typedef EVP_CIPHER_CTX cipher_evp_t;
typedef EVP_MD digest_type_t;
#define MAX_KEY_LENGTH EVP_MAX_KEY_LENGTH
#define MAX_IV_LENGTH EVP_MAX_IV_LENGTH
#define MAX_MD_SIZE EVP_MAX_MD_SIZE
//OPENSSL end

typedef quint8 uint8_t;
typedef quint16 uint16_t;
typedef quint32 uint32_t;
typedef quint64 uint64_t;

typedef struct
{
    cipher_evp_t evp;
} cipher_ctx_t;

#define BLOCK_SIZE 32

#define CIPHER_NUM          14
#define NONE                -1
#define TABLE               0
#define RC4                 1
#define AES_128_CFB         2
#define AES_192_CFB         3
#define AES_256_CFB         4
#define BF_CFB              5
#define CAMELLIA_128_CFB    6
#define CAMELLIA_192_CFB    7
#define CAMELLIA_256_CFB    8
#define CAST5_CFB           9
#define DES_CFB             10
#define IDEA_CFB            11
#define RC2_CFB             12
#define SEED_CFB            13

#define min(a,b) (((a)<(b))?(a):(b))
#define max(a,b) (((a)>(b))?(a):(b))

struct enc_ctx
{
    uint8_t init;
    cipher_ctx_t evp;
};

class encrypt : public QObject
{
    Q_OBJECT
public:
    explicit encrypt(QString pass, QString method, QObject *parent = 0);
    ~encrypt();

    void init_ctx(struct enc_ctx *ctx, bool encode);
    char* ss_encrypt_all(int buf_size, char *plaintext, ssize_t *len, int method);
    char* ss_decrypt_all(int buf_size, char *ciphertext, ssize_t *len, int method);
    //char* ss_encrypt(int buf_size, char *plaintext, ssize_t *len, struct enc_ctx *ctx, uint8_t init);
    QByteArray* ss_encrypt(int buf_size, QByteArray *out,QByteArray *in, ssize_t *len, struct enc_ctx *ctx);
    QByteArray* ss_decrypt(int buf_size, QByteArray *out,QByteArray *in, ssize_t *len, struct enc_ctx *ctx);
    void enc_ctx_init(int method, enc_ctx *ctx, int enc);
    int enc_init(QString pass, QString method);
    int enc_get_iv_len(void);
    void cipher_context_release(cipher_ctx_t *evp);
    unsigned char *enc_md5(const unsigned char *d, size_t n, unsigned char *md);

    //inner functions
    void enc_table_init(const char *pass);
    int cipher_iv_size(const cipher_kt_t *cipher);
    int cipher_key_size (const cipher_kt_t *cipher);
    void enc_key_init(int method, const char *pass);
    void cipher_context_init(cipher_ctx_t *ctx, int method, int enc);
    int rand_bytes(uint8_t *output, int len);
    void cipher_context_set_iv(cipher_ctx_t *ctx, uint8_t *iv, size_t iv_len, int enc);
    int bytes_to_key(const cipher_kt_t *cipher, const digest_type_t *md, const uint8_t *pass, uint8_t *key, uint8_t *iv);


    int method_crypt;

signals:

public slots:

private:
    uint8_t *enc_table;
    uint8_t *dec_table;
    uint8_t enc_key[MAX_KEY_LENGTH];
    int enc_key_len;
    int enc_iv_len;

};

#endif // ENCRYPT_H

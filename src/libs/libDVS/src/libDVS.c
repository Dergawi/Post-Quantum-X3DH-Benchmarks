#include "../include/header_DVS.h"
#include "../../raptor/raptor.h"

int64_t *H;

int initiate_DVS() {

    unsigned char *seedH;

    seedH = malloc(SEEDLEN);
    H = malloc(sizeof(int64_t) * DIM);
    randombytes(seedH, SEEDLEN);
    pol_unidrnd_with_seed(H, DIM, PARAM_Q, seedH, SEEDLEN);

    free(seedH);

    return 0;
}

int key_gen_signer_DVS(secret_key_signer_DVS *secret_key_signer_DVS,
                       public_key_signer_DVS *public_key_signer_DVS) {

    raptor_data public_key_tmp;

    public_key_tmp.c = NULL;
    public_key_tmp.d = NULL;
    public_key_tmp.r0 = NULL;
    public_key_tmp.r1 = NULL;
    public_key_tmp.h = NULL;

    secret_key_signer_DVS->secret_key_content = NULL;

    public_key_tmp.c = malloc(sizeof(int64_t) * DIM);
    public_key_tmp.d = malloc(sizeof(int64_t) * DIM);
    public_key_tmp.r0 = malloc(sizeof(int64_t) * DIM);
    public_key_tmp.r1 = malloc(sizeof(int64_t) * DIM);
    public_key_tmp.h = malloc(sizeof(int64_t) * DIM);

    secret_key_signer_DVS->secret_key_content = malloc(CRYPTO_SECRETKEYBYTES);

    raptor_keygen(public_key_tmp,
                  (unsigned char *)secret_key_signer_DVS->secret_key_content);

    public_key_signer_DVS->public_key_content = malloc(sizeof(int64_t) * DIM);
    memcpy(public_key_signer_DVS->public_key_content, public_key_tmp.h,
           sizeof(int64_t) * DIM);

    public_key_signer_DVS->public_key_length = sizeof(int64_t) * DIM;
    secret_key_signer_DVS->secret_key_length = CRYPTO_SECRETKEYBYTES;

    free(public_key_tmp.c);
    free(public_key_tmp.d);
    free(public_key_tmp.r0);
    free(public_key_tmp.r1);
    free(public_key_tmp.h);

    return 0;
}

int key_gen_verifier_DVS(secret_key_verifier_DVS *secret_key_verifier_DVS,
                         public_key_verifier_DVS *public_key_verifier_DVS) {

    raptor_data public_key_tmp;

    public_key_tmp.c = NULL;
    public_key_tmp.d = NULL;
    public_key_tmp.r0 = NULL;
    public_key_tmp.r1 = NULL;
    public_key_tmp.h = NULL;

    secret_key_verifier_DVS->secret_key_content = NULL;

    public_key_tmp.c = malloc(sizeof(int64_t) * DIM);
    public_key_tmp.d = malloc(sizeof(int64_t) * DIM);
    public_key_tmp.r0 = malloc(sizeof(int64_t) * DIM);
    public_key_tmp.r1 = malloc(sizeof(int64_t) * DIM);
    public_key_tmp.h = malloc(sizeof(int64_t) * DIM);

    secret_key_verifier_DVS->secret_key_content = malloc(CRYPTO_SECRETKEYBYTES);

    raptor_keygen(public_key_tmp,
                  (unsigned char *)secret_key_verifier_DVS->secret_key_content);

    public_key_verifier_DVS->public_key_content = malloc(sizeof(int64_t) * DIM);
    memcpy(public_key_verifier_DVS->public_key_content, public_key_tmp.h,
           sizeof(int64_t) * DIM);

    public_key_verifier_DVS->public_key_length = sizeof(int64_t) * DIM;
    secret_key_verifier_DVS->secret_key_length = CRYPTO_SECRETKEYBYTES;

    free(public_key_tmp.c);
    free(public_key_tmp.d);
    free(public_key_tmp.r0);
    free(public_key_tmp.r1);
    free(public_key_tmp.h);

    return 0;
}

int sign_DVS(secret_key_signer_DVS *secret_key_signer_DVS, message *message,
             public_key_signer_DVS *public_key_signer_DVS,
             public_key_verifier_DVS *public_key_verifier_DVS,
             signature *signature) {

    raptor_data signature_tmp[2];

    for (int i = 0; i < 2; i++) {
        signature_tmp[i].c = malloc(sizeof(int64_t) * DIM);
        signature_tmp[i].d = malloc(sizeof(int64_t) * DIM);
        signature_tmp[i].r0 = malloc(sizeof(int64_t) * DIM);
        signature_tmp[i].r1 = malloc(sizeof(int64_t) * DIM);
        signature_tmp[i].h = malloc(sizeof(int64_t) * DIM);
    }

    memcpy(signature_tmp[0].h, public_key_verifier_DVS->public_key_content,
           sizeof(int64_t) * DIM);
    memcpy(signature_tmp[1].h, public_key_signer_DVS->public_key_content,
           sizeof(int64_t) * DIM);

    if (raptor_sign(message->message_content, message->message_length,
                    signature_tmp,
                    (unsigned char *)secret_key_signer_DVS->secret_key_content,
                    H) < 0) {
        fprintf(stderr, "error_sign\n");
        return 1;
    }

    signature->signature_content = malloc(8 * sizeof(int64_t) * DIM);

    void *p = signature->signature_content;

    for (int i = 0; i < 2; i++) {
        memcpy(p, signature_tmp[i].c, sizeof(int64_t) * DIM);
        p = p + sizeof(int64_t) * DIM;
        memcpy(p, signature_tmp[i].d, sizeof(int64_t) * DIM);
        p = p + sizeof(int64_t) * DIM;
        memcpy(p, signature_tmp[i].r0, sizeof(int64_t) * DIM);
        p = p + sizeof(int64_t) * DIM;
        memcpy(p, signature_tmp[i].r1, sizeof(int64_t) * DIM);
        p = p + sizeof(int64_t) * DIM;
    }

    signature->signature_length = 8 * sizeof(int64_t) * DIM;

    for (int i = 0; i < 2; i++) {
        free(signature_tmp[i].c);
        free(signature_tmp[i].d);
        free(signature_tmp[i].r0);
        free(signature_tmp[i].r1);
        free(signature_tmp[i].h);
    }

    return 0;
}

int simulate_DVS(secret_key_verifier_DVS *secret_key_verifier_DVS,
                 message *message, public_key_signer_DVS *public_key_signer_DVS,
                 public_key_verifier_DVS *public_key_verifier_DVS,
                 signature *signature) {

    raptor_data signature_tmp[2];

    for (int i = 0; i < 2; i++) {
        signature_tmp[i].c = malloc(sizeof(int64_t) * DIM);
        signature_tmp[i].d = malloc(sizeof(int64_t) * DIM);
        signature_tmp[i].r0 = malloc(sizeof(int64_t) * DIM);
        signature_tmp[i].r1 = malloc(sizeof(int64_t) * DIM);
        signature_tmp[i].h = malloc(sizeof(int64_t) * DIM);
    }

    memcpy(signature_tmp[0].h, public_key_signer_DVS->public_key_content,
           sizeof(int64_t) * DIM);
    memcpy(signature_tmp[1].h, public_key_verifier_DVS->public_key_content,
           sizeof(int64_t) * DIM);

    if (raptor_sign(
            message->message_content, message->message_length, signature_tmp,
            (unsigned char *)secret_key_verifier_DVS->secret_key_content,
            H) < 0) {
        fprintf(stderr, "error_sign\n");
        return 1;
    }

    signature->signature_content = malloc(8 * sizeof(int64_t) * DIM);

    void *p = signature->signature_content;

    for (int i = 0; i < 2; i++) {
        memcpy(p, signature_tmp[i].c, sizeof(int64_t) * DIM);
        p = p + sizeof(int64_t) * DIM;
        memcpy(p, signature_tmp[i].d, sizeof(int64_t) * DIM);
        p = p + sizeof(int64_t) * DIM;
        memcpy(p, signature_tmp[i].r0, sizeof(int64_t) * DIM);
        p = p + sizeof(int64_t) * DIM;
        memcpy(p, signature_tmp[i].r1, sizeof(int64_t) * DIM);
        p = p + sizeof(int64_t) * DIM;
    }

    signature->signature_length = 8 * sizeof(int64_t) * DIM;

    for (int i = 0; i < 2; i++) {
        free(signature_tmp[i].c);
        free(signature_tmp[i].d);
        free(signature_tmp[i].r0);
        free(signature_tmp[i].r1);
        free(signature_tmp[i].h);
    }

    return 0;
}

int verify_DVS(signature *signature, message *message,
               public_key_signer_DVS *public_key_signer_DVS,
               public_key_verifier_DVS *public_key_verifier_DVS) {

    raptor_data signature_tmp[2];

    for (int i = 0; i < 2; i++) {
        signature_tmp[i].c = malloc(sizeof(int64_t) * DIM);
        signature_tmp[i].d = malloc(sizeof(int64_t) * DIM);
        signature_tmp[i].r0 = malloc(sizeof(int64_t) * DIM);
        signature_tmp[i].r1 = malloc(sizeof(int64_t) * DIM);
        signature_tmp[i].h = malloc(sizeof(int64_t) * DIM);
    }

    void *p = signature->signature_content;

    for (int i = 0; i < 2; i++) {
        memcpy(signature_tmp[i].c, p, sizeof(int64_t) * DIM);
        p = p + sizeof(int64_t) * DIM;
        memcpy(signature_tmp[i].d, p, sizeof(int64_t) * DIM);
        p = p + sizeof(int64_t) * DIM;
        memcpy(signature_tmp[i].r0, p, sizeof(int64_t) * DIM);
        p = p + sizeof(int64_t) * DIM;
        memcpy(signature_tmp[i].r1, p, sizeof(int64_t) * DIM);
        p = p + sizeof(int64_t) * DIM;
    }

    memcpy(signature_tmp[0].h, public_key_verifier_DVS->public_key_content,
           sizeof(int64_t) * DIM);
    memcpy(signature_tmp[1].h, public_key_signer_DVS->public_key_content,
           sizeof(int64_t) * DIM);

    if (raptor_verify(message->message_content, message->message_length,
                      signature_tmp, H) != 0) {

        memcpy(signature_tmp[0].h, public_key_signer_DVS->public_key_content,
               sizeof(int64_t) * DIM);
        memcpy(signature_tmp[1].h, public_key_verifier_DVS->public_key_content,
               sizeof(int64_t) * DIM);

        if (raptor_verify(message->message_content, message->message_length,
                          signature_tmp, H) != 0) {
            fprintf(stderr, "error_verify\n");
            return 1;
        }
    }

    for (int i = 0; i < 2; i++) {
        free(signature_tmp[i].c);
        free(signature_tmp[i].d);
        free(signature_tmp[i].r0);
        free(signature_tmp[i].r1);
        free(signature_tmp[i].h);
    }

    return 0;
}

int terminate_DVS() {

    free(H);

    return 0;
}

void free_key_pair_signer_DVS(secret_key_signer_DVS *secret_key_signer_DVS,
                              public_key_signer_DVS *public_key_signer_DVS) {

    free(public_key_signer_DVS->public_key_content);

    free((unsigned char *)secret_key_signer_DVS->secret_key_content);

    return;
}

void free_key_pair_verifier_DVS(
    secret_key_verifier_DVS *secret_key_verifier_DVS,
    public_key_verifier_DVS *public_key_verifier_DVS) {

    free(public_key_verifier_DVS->public_key_content);

    free((unsigned char *)secret_key_verifier_DVS->secret_key_content);

    return;
}

void free_message(message *message) {

    free(message->message_content);

    return;
}

void free_signature(signature *signature) {

    free(signature->signature_content);

    return;
}

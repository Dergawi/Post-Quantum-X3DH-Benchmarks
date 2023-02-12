#include <stdlib.h>
#include <string.h>
#include <openssl/rand.h>

#include "../../lwe-frodo/lwe.h"
#include "../../lwe-frodo/lwekex.h"
#include "../include/header_SplitKEM.h"

uint8_t *seed;

int initiate_SKEM() {

    seed = NULL;
    seed = malloc(LWE_SEED_LENGTH);

    RAND_bytes(seed, LWE_SEED_LENGTH);

    return 0;
}

int key_gen_SKEM(secret_key_SKEM *secret_key_SKEM,
                 public_key_SKEM *public_key_SKEM) {

    public_key_SKEM->public_key_content = malloc(2 * LWE_PUB_LENGTH + 8);
    secret_key_SKEM->secret_key_content =
        malloc(2 * LWE_N * LWE_N_BAR * sizeof(uint16_t));

    LWE_PAIR *key_pair = NULL;

    key_pair = LWE_PAIR_new();

    LWE_PAIR_generate_key(key_pair, 0, seed);

    void *p = public_key_SKEM->public_key_content;
    memcpy(p, key_pair->pub->b, LWE_PUB_LENGTH);
    p = secret_key_SKEM->secret_key_content;
    memcpy(p, key_pair->s, LWE_N * LWE_N_BAR * sizeof(uint16_t));

    LWE_PAIR_free(key_pair);

    key_pair = NULL;

    key_pair = LWE_PAIR_new();

    LWE_PAIR_generate_key(key_pair, 1, seed);

    p = public_key_SKEM->public_key_content;
    p = p + LWE_PUB_LENGTH;
    memcpy(p, key_pair->pub->b, LWE_PUB_LENGTH);
    p = p + LWE_PUB_LENGTH;
    memcpy(p, key_pair->pub->param->seed, 8);
    p = secret_key_SKEM->secret_key_content;
    p = p + LWE_N * LWE_N_BAR * sizeof(uint16_t);
    memcpy(p, key_pair->s, LWE_N * LWE_N_BAR * sizeof(uint16_t));

    public_key_SKEM->public_key_length = 2 * LWE_PUB_LENGTH + 8;
    secret_key_SKEM->secret_key_length =
        2 * LWE_N * LWE_N_BAR * sizeof(uint16_t);

    LWE_PAIR_free(key_pair);

    return 0;
}

int encapsulate_SKEM(secret_key_SKEM *secret_key_encapsulator_SKEM,
                     public_key_SKEM *public_key_encapsulator_SKEM,
                     public_key_SKEM *public_key_decapsulator_SKEM,
                     ciphertext *ciphertext, shared_secret *shared_secret) {

    LWE_PUB *public_key_decapsulator = NULL;
    LWE_PAIR *key_pair_encapsulator = NULL;
    LWE_REC *reconciliation_function = NULL;
    uint16_t v[LWE_N_BAR * LWE_N_BAR];

    shared_secret->shared_secret_content = malloc(LWE_KEY_BITS / 8);
    shared_secret->shared_secret_length = LWE_KEY_BITS / 8;

    public_key_decapsulator = LWE_PUB_new();
    public_key_decapsulator->param = LWE_PARAM_new();

    key_pair_encapsulator = LWE_PAIR_new();
    key_pair_encapsulator->pub = LWE_PUB_new();
    key_pair_encapsulator->pub->param = LWE_PARAM_new();

    reconciliation_function = LWE_REC_new();

    void *q = public_key_decapsulator_SKEM->public_key_content;
    q = q + LWE_PUB_LENGTH;
    memcpy(public_key_decapsulator->b, q, LWE_PUB_LENGTH);
    q = q + LWE_PUB_LENGTH;
    memcpy(public_key_decapsulator->param->seed, q, 8);

    q = public_key_encapsulator_SKEM->public_key_content;
    memcpy(key_pair_encapsulator->pub->b, q, LWE_PUB_LENGTH);
    q = q + 2 * LWE_PUB_LENGTH;
    memcpy(key_pair_encapsulator->pub->param->seed, q, 8);
    q = secret_key_encapsulator_SKEM->secret_key_content;
    memcpy(key_pair_encapsulator->s, q, LWE_N * LWE_N_BAR * sizeof(uint16_t));

    LWEKEX_compute_key_bob(shared_secret->shared_secret_content,
                           shared_secret->shared_secret_length,
                           reconciliation_function, public_key_decapsulator,
                           key_pair_encapsulator, v);

    ciphertext->ciphertext_content = malloc(LWE_REC_HINT_LENGTH);
    ciphertext->ciphertext_length = LWE_REC_HINT_LENGTH;

    q = ciphertext->ciphertext_content;
    memcpy(q, reconciliation_function->c, LWE_REC_HINT_LENGTH);

    LWE_REC_free(reconciliation_function);
    LWE_PUB_free(public_key_decapsulator);
    LWE_PAIR_free(key_pair_encapsulator);

    return 0;
}

int decapsulate_SKEM(secret_key_SKEM *secret_key_decapsulator_SKEM,
                     public_key_SKEM *public_key_decapsulator_SKEM,
                     public_key_SKEM *public_key_encapsulator_SKEM,
                     ciphertext *ciphertext, shared_secret *shared_secret) {

    LWE_PAIR *key_pair_decapsulator = NULL;
    LWE_PUB *public_key_encapsulator = NULL;
    LWE_REC *reconciliation_function = NULL;
    uint16_t w[LWE_N_BAR * LWE_N_BAR];

    shared_secret->shared_secret_content = malloc(LWE_KEY_BITS / 8);
    shared_secret->shared_secret_length = LWE_KEY_BITS / 8;

    key_pair_decapsulator = LWE_PAIR_new();
    key_pair_decapsulator->pub = LWE_PUB_new();
    key_pair_decapsulator->pub->param = LWE_PARAM_new();

    public_key_encapsulator = LWE_PUB_new();
    public_key_encapsulator->param = LWE_PARAM_new();

    reconciliation_function = LWE_REC_new();

    void *q = public_key_decapsulator_SKEM->public_key_content;
    q = q + LWE_PUB_LENGTH;
    memcpy(key_pair_decapsulator->pub->b, q, LWE_PUB_LENGTH);
    q = q + LWE_PUB_LENGTH;
    memcpy(key_pair_decapsulator->pub->param->seed, q, 8);
    q = secret_key_decapsulator_SKEM->secret_key_content;
    q = q + LWE_N * LWE_N_BAR * sizeof(uint16_t);
    memcpy(key_pair_decapsulator->s, q, LWE_N * LWE_N_BAR * sizeof(uint16_t));

    q = public_key_encapsulator_SKEM->public_key_content;
    memcpy(public_key_encapsulator->b, q, LWE_PUB_LENGTH);
    q = q + 2 * LWE_PUB_LENGTH;
    memcpy(public_key_encapsulator->param->seed, q, 8);

    memcpy(reconciliation_function->c, ciphertext->ciphertext_content,
           ciphertext->ciphertext_length);

    LWEKEX_compute_key_alice(shared_secret->shared_secret_content,
                             shared_secret->shared_secret_length,
                             public_key_encapsulator, reconciliation_function,
                             key_pair_decapsulator, w);

    LWE_REC_free(reconciliation_function);
    LWE_PUB_free(public_key_encapsulator);
    LWE_PAIR_free(key_pair_decapsulator);

    return 0;
}

int terminate_SKEM() {

    free(seed);

    return 0;
}

void free_key_pair_SKEM(secret_key_SKEM *secret_key_SKEM,
                        public_key_SKEM *public_key_SKEM) {

    free(public_key_SKEM->public_key_content);
    free(secret_key_SKEM->secret_key_content);

    return;
}

void free_ciphertext_SKEM(ciphertext *ciphertext) {

    free(ciphertext->ciphertext_content);

    return;
}

void free_shared_secret_SKEM(shared_secret *shared_secret) {

    free(shared_secret->shared_secret_content);

    return;
}

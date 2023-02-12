#include "libProtocol.h"

#define CONTEXT "X3DH_classic"
#define HASH_LENGTH 32

int initiate_protocol() { return 0; }

int long_term_key_gen(secret_key_DH *secret_key_DH,
                      public_key_DH *public_key_DH) {

    public_key_DH->public_key_content = NULL;
    secret_key_DH->secret_key_content = NULL;

    public_key_DH->public_key_content = malloc(crypto_sign_PUBLICKEYBYTES);
    secret_key_DH->secret_key_content = malloc(crypto_sign_SECRETKEYBYTES);

    if ((public_key_DH->public_key_content == NULL) ||
        (secret_key_DH->secret_key_content == NULL)) {
        fprintf(stderr, "ERROR: malloc failed!\n");
        return 1;
    }

    crypto_sign_keypair(public_key_DH->public_key_content,
                        secret_key_DH->secret_key_content);

    public_key_DH->public_key_length = crypto_sign_PUBLICKEYBYTES;
    secret_key_DH->secret_key_length = crypto_sign_SECRETKEYBYTES;

    return 0;
}

int static_key_gen(secret_key_DH *long_term_secret_key_DH,
                   secret_key_DH *static_secret_key_DH,
                   public_key_DH *static_public_key_DH, signature *signature) {

    static_public_key_DH->public_key_content = NULL;
    static_secret_key_DH->secret_key_content = NULL;
    signature->signature_content = NULL;

    static_public_key_DH->public_key_content =
        malloc(crypto_box_PUBLICKEYBYTES);
    static_secret_key_DH->secret_key_content =
        malloc(crypto_box_SECRETKEYBYTES);
    signature->signature_content = malloc(crypto_sign_BYTES);

    if ((static_public_key_DH->public_key_content == NULL) ||
        (static_secret_key_DH->secret_key_content == NULL) ||
        (signature->signature_content == NULL)) {
        fprintf(stderr, "ERROR: malloc failed!\n");
        return 1;
    }

    crypto_box_keypair(static_public_key_DH->public_key_content,
                       static_secret_key_DH->secret_key_content);

    crypto_sign_detached(signature->signature_content,
                         (long long unsigned int *)&signature->signature_length,
                         static_public_key_DH->public_key_content,
                         crypto_box_PUBLICKEYBYTES,
                         long_term_secret_key_DH->secret_key_content);

    static_public_key_DH->public_key_length = crypto_box_PUBLICKEYBYTES;
    static_secret_key_DH->secret_key_length = crypto_box_SECRETKEYBYTES;
    signature->signature_length = crypto_sign_BYTES;

    return 0;
}

int one_time_key_gen(secret_key_DH *secret_key_DH,
                     public_key_DH *public_key_DH) {

    public_key_DH->public_key_content = NULL;
    secret_key_DH->secret_key_content = NULL;

    public_key_DH->public_key_content = malloc(crypto_box_PUBLICKEYBYTES);
    secret_key_DH->secret_key_content = malloc(crypto_box_SECRETKEYBYTES);

    if ((public_key_DH->public_key_content == NULL) ||
        (secret_key_DH->secret_key_content == NULL)) {
        fprintf(stderr, "ERROR: malloc failed!\n");
        return 1;
    }

    crypto_box_keypair(public_key_DH->public_key_content,
                       secret_key_DH->secret_key_content);

    public_key_DH->public_key_length = crypto_box_PUBLICKEYBYTES;
    secret_key_DH->secret_key_length = crypto_box_SECRETKEYBYTES;

    return 0;
}

int initiator(secret_key_DH *long_term_secret_key_DH_initiator,
              public_key_DH *long_term_public_key_DH_responder,
              public_key_DH *static_public_key_DH,
              public_key_DH *one_time_public_key_DH,
              secret_key_DH *ephemeral_secret_key_DH,
              public_key_DH *ephemeral_public_key_DH, signature *signature) {

    uint8_t long_term_initiator_secret_key_converted[crypto_box_SECRETKEYBYTES],
        long_term_responder_public_key_converted[crypto_box_SECRETKEYBYTES];
    uint8_t shared_secret_1[crypto_box_BEFORENMBYTES],
        shared_secret_2[crypto_box_BEFORENMBYTES],
        shared_secret_3[crypto_box_BEFORENMBYTES],
        shared_secret_4[crypto_box_BEFORENMBYTES];
    uint8_t shared_key[HASH_LENGTH], pre_key[HASH_LENGTH];
    crypto_generichash_state hash_state;

    if (crypto_sign_verify_detached(
            signature->signature_content,
            static_public_key_DH->public_key_content, crypto_box_PUBLICKEYBYTES,
            long_term_public_key_DH_responder->public_key_content) != 0) {
        fprintf(stderr, "ERROR: static key verification failed");
        return 1;
    }

    one_time_key_gen(ephemeral_secret_key_DH, ephemeral_public_key_DH);

    crypto_sign_ed25519_sk_to_curve25519(
        long_term_initiator_secret_key_converted,
        long_term_secret_key_DH_initiator->secret_key_content);
    crypto_sign_ed25519_pk_to_curve25519(
        long_term_responder_public_key_converted,
        long_term_public_key_DH_responder->public_key_content);
    crypto_box_beforenm(shared_secret_1,
                        static_public_key_DH->public_key_content,
                        long_term_initiator_secret_key_converted);
    crypto_box_beforenm(shared_secret_2,
                        long_term_responder_public_key_converted,
                        ephemeral_secret_key_DH->secret_key_content);
    crypto_box_beforenm(shared_secret_3,
                        static_public_key_DH->public_key_content,
                        ephemeral_secret_key_DH->secret_key_content);
    crypto_box_beforenm(shared_secret_4,
                        one_time_public_key_DH->public_key_content,
                        ephemeral_secret_key_DH->secret_key_content);

    // The parameters NULL and 0 indicates that we don't use a key for the hash
    // function. It will be the case for all hash function of the library
    // "libsodium"
    crypto_generichash_init(&hash_state, NULL, 0, HASH_LENGTH);
    crypto_generichash_update(&hash_state, shared_secret_1,
                              crypto_box_BEFORENMBYTES);
    crypto_generichash_update(&hash_state, shared_secret_2,
                              crypto_box_BEFORENMBYTES);
    crypto_generichash_update(&hash_state, shared_secret_3,
                              crypto_box_BEFORENMBYTES);
    crypto_generichash_update(&hash_state, shared_secret_4,
                              crypto_box_BEFORENMBYTES);
    crypto_generichash_final(&hash_state, pre_key, HASH_LENGTH);

    crypto_kdf_derive_from_key(shared_key, sizeof shared_key, 1, CONTEXT,
                               pre_key);

    return 0;
}

int responder(public_key_DH *long_term_public_key_DH_initiator,
              secret_key_DH *long_term_secret_key_DH_responder,
              secret_key_DH *static_secret_key_DH,
              secret_key_DH *one_time_secret_key_DH,
              public_key_DH *ephemeral_public_key_DH) {

    uint8_t long_term_initiator_public_key_converted[crypto_box_PUBLICKEYBYTES],
        long_term_responder_secret_key_converted[crypto_box_PUBLICKEYBYTES];
    uint8_t shared_secret_1[crypto_box_BEFORENMBYTES],
        shared_secret_2[crypto_box_BEFORENMBYTES],
        shared_secret_3[crypto_box_BEFORENMBYTES],
        shared_secret_4[crypto_box_BEFORENMBYTES];
    uint8_t shared_key[HASH_LENGTH], pre_key[HASH_LENGTH];
    crypto_generichash_state hash_state;

    crypto_sign_ed25519_pk_to_curve25519(
        long_term_initiator_public_key_converted,
        long_term_public_key_DH_initiator->public_key_content);
    crypto_sign_ed25519_sk_to_curve25519(
        long_term_responder_secret_key_converted,
        long_term_secret_key_DH_responder->secret_key_content);
    crypto_box_beforenm(shared_secret_1,
                        long_term_initiator_public_key_converted,
                        static_secret_key_DH->secret_key_content);
    crypto_box_beforenm(shared_secret_2,
                        ephemeral_public_key_DH->public_key_content,
                        long_term_responder_secret_key_converted);
    crypto_box_beforenm(shared_secret_3,
                        ephemeral_public_key_DH->public_key_content,
                        static_secret_key_DH->secret_key_content);
    crypto_box_beforenm(shared_secret_4,
                        ephemeral_public_key_DH->public_key_content,
                        one_time_secret_key_DH->secret_key_content);

    // The parameters NULL and 0 indicates that we don't use a key for the hash
    // function. It will be the case for all hash function of the library
    // "libsodium"
    crypto_generichash_init(&hash_state, NULL, 0, HASH_LENGTH);
    crypto_generichash_update(&hash_state, shared_secret_1,
                              crypto_box_BEFORENMBYTES);
    crypto_generichash_update(&hash_state, shared_secret_2,
                              crypto_box_BEFORENMBYTES);
    crypto_generichash_update(&hash_state, shared_secret_3,
                              crypto_box_BEFORENMBYTES);
    crypto_generichash_update(&hash_state, shared_secret_4,
                              crypto_box_BEFORENMBYTES);
    crypto_generichash_final(&hash_state, pre_key, HASH_LENGTH);

    crypto_kdf_derive_from_key(shared_key, sizeof shared_key, 1, CONTEXT,
                               pre_key);

    return 0;
}

void free_key_pair(secret_key_DH *secret_key_DH, public_key_DH *public_key_DH) {

    free(public_key_DH->public_key_content);
    free(secret_key_DH->secret_key_content);

    return;
}

void free_signature(signature *signature) {

    free(signature->signature_content);

    return;
}
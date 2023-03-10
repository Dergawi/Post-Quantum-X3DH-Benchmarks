#include "libProtocol.h"

#define CONTEXT "KEM_SIG"

int initiate_protocol(const char *KEM_scheme_name,
                      const char *SIG_scheme_name) {

    instantiate_KEM(KEM_scheme_name);

    instantiate_SIG(SIG_scheme_name);

    return 0;
}

int long_term_key_gen(long_term_secret_key *long_term_secret_key,
                      long_term_public_key *long_term_public_key) {

    long_term_public_key->public_key_KEM = malloc(sizeof(public_key_KEM));
    long_term_public_key->public_key_SIG = malloc(sizeof(public_key_SIG));
    long_term_secret_key->secret_key_KEM = malloc(sizeof(secret_key_KEM));
    long_term_secret_key->secret_key_SIG = malloc(sizeof(secret_key_SIG));

    if (key_gen_KEM(long_term_secret_key->secret_key_KEM,
                    long_term_public_key->public_key_KEM) < 0) {
        fprintf(stderr, "ERROR: KEM key pair generation failed! \n");
        return 1;
    }

    if (key_gen_SIG(long_term_secret_key->secret_key_SIG,
                    long_term_public_key->public_key_SIG) < 0) {
        fprintf(stderr, "ERROR: SIG key pair generation failed! \n");
        return 2;
    }

    long_term_public_key->public_key_length =
        long_term_public_key->public_key_KEM->public_key_length +
        long_term_public_key->public_key_SIG->public_key_length;
    long_term_secret_key->secret_key_length =
        long_term_secret_key->secret_key_KEM->secret_key_length +
        long_term_secret_key->secret_key_SIG->secret_key_length;

    return 0;
}

int static_key_gen(static_secret_key *static_secret_key,
                   long_term_secret_key *long_term_secret_key,
                   static_public_key *static_public_key) {

    static_public_key->public_key_KEM = malloc(sizeof(public_key_KEM));
    static_public_key->signature = malloc(sizeof(signature_SIG));
    static_secret_key->secret_key_KEM = malloc(sizeof(secret_key_KEM));

    message_SIG public_keys_signature;

    if (key_gen_KEM(static_secret_key->secret_key_KEM,
                    static_public_key->public_key_KEM) < 0) {
        fprintf(stderr, "ERROR: KEM key pair generation failed! \n");
        return 1;
    }

    public_keys_signature.message_content =
        malloc(static_public_key->public_key_KEM->public_key_length);
    memcpy(public_keys_signature.message_content,
           static_public_key->public_key_KEM->public_key_content,
           static_public_key->public_key_KEM->public_key_length);
    public_keys_signature.message_length =
        static_public_key->public_key_KEM->public_key_length;

    if (sign_SIG(long_term_secret_key->secret_key_SIG, &public_keys_signature,
                 static_public_key->signature) < 0) {
        fprintf(stderr, "ERROR: SIG key pair generation failed! \n");
        return 2;
    }

    static_public_key->public_key_length =
        static_public_key->public_key_KEM->public_key_length +
        static_public_key->signature->signature_length;
    static_secret_key->secret_key_length =
        static_secret_key->secret_key_KEM->secret_key_length;

    free_message_SIG(&public_keys_signature);

    return 0;
}

int one_time_key_gen(one_time_secret_key *one_time_secret_key,
                     one_time_public_key *one_time_public_key) {

    one_time_public_key->public_key_KEM = malloc(sizeof(public_key_KEM));
    one_time_secret_key->secret_key_KEM = malloc(sizeof(secret_key_KEM));

    if (key_gen_KEM(one_time_secret_key->secret_key_KEM,
                    one_time_public_key->public_key_KEM) < 0) {
        fprintf(stderr, "ERROR: KEM key pair generation failed! \n");
        return 1;
    }

    one_time_public_key->public_key_length =
        one_time_public_key->public_key_KEM->public_key_length;
    one_time_secret_key->secret_key_length =
        one_time_secret_key->secret_key_KEM->secret_key_length;

    return 0;
}

int initiator(long_term_public_key *long_term_public_key_responder,
              static_public_key *static_public_key_responder,
              one_time_public_key *one_time_public_key_responder,
              ciphertext *ciphertext_1, ciphertext *ciphertext_2,
              ciphertext *ciphertext_3, size_t security_parameter) {

    uint8_t shared_key[security_parameter], pre_key[HASH_LENGTH];
    crypto_generichash_state hash_state;
    shared_secret shared_secret_1, shared_secret_2, shared_secret_3;
    message_SIG public_keys_signature;

    public_keys_signature.message_content =
        malloc(static_public_key_responder->public_key_KEM->public_key_length);
    memcpy(public_keys_signature.message_content,
           static_public_key_responder->public_key_KEM->public_key_content,
           static_public_key_responder->public_key_KEM->public_key_length);
    public_keys_signature.message_length =
        static_public_key_responder->public_key_KEM->public_key_length;

    if (verify_SIG(long_term_public_key_responder->public_key_SIG,
                   &public_keys_signature,
                   static_public_key_responder->signature)) {
        fprintf(stderr, "ERROR: SIG failed! \n");
        return 1;
    }

    if (encapsulate_KEM(long_term_public_key_responder->public_key_KEM,
                        ciphertext_1, &shared_secret_1) < 0) {
        fprintf(stderr, "ERROR: encapsulation failed! \n");
        return 3;
    }
    if (encapsulate_KEM(static_public_key_responder->public_key_KEM,
                        ciphertext_2, &shared_secret_2) < 0) {
        fprintf(stderr, "ERROR: encapsulation failed! \n");
        return 3;
    }
    if (encapsulate_KEM(one_time_public_key_responder->public_key_KEM,
                        ciphertext_3, &shared_secret_3) < 0) {
        fprintf(stderr, "ERROR: encapsulation failed! \n");
        return 3;
    }

    crypto_generichash_init(&hash_state, NULL, 0, HASH_LENGTH);
    crypto_generichash_update(
        &hash_state, (unsigned char *)shared_secret_1.shared_secret_content,
        crypto_box_BEFORENMBYTES);
    crypto_generichash_update(
        &hash_state, (unsigned char *)shared_secret_2.shared_secret_content,
        crypto_box_BEFORENMBYTES);
    crypto_generichash_update(
        &hash_state, (unsigned char *)shared_secret_3.shared_secret_content,
        crypto_box_BEFORENMBYTES);
    crypto_generichash_final(&hash_state, pre_key, HASH_LENGTH);

    crypto_kdf_derive_from_key(shared_key, sizeof shared_key, 1, CONTEXT,
                               pre_key);

    free_message_SIG(&public_keys_signature);
    free_shared_secret_KEM(&shared_secret_1);
    free_shared_secret_KEM(&shared_secret_2);
    free_shared_secret_KEM(&shared_secret_3);

    return 0;
}

int responder(long_term_secret_key *long_term_secret_key_responder,
              static_secret_key *static_secret_key_responder,
              one_time_secret_key *one_time_secret_key_responder,
              ciphertext *ciphertext_1, ciphertext *ciphertext_2,
              ciphertext *ciphertext_3, size_t security_parameter) {

    uint8_t shared_key[security_parameter], pre_key[HASH_LENGTH];
    crypto_generichash_state hash_state;
    shared_secret shared_secret_1, shared_secret_2, shared_secret_3;

    // We reverse what we did in the initiator function

    if (decapsulate_KEM(long_term_secret_key_responder->secret_key_KEM,
                        ciphertext_1, &shared_secret_1) < 0) {
        fprintf(stderr, "ERROR: decapsulation failed! \n");
        return 1;
    }
    if (decapsulate_KEM(static_secret_key_responder->secret_key_KEM,
                        ciphertext_2, &shared_secret_2) < 0) {
        fprintf(stderr, "ERROR: decapsulation failed! \n");
        return 1;
    }
    if (decapsulate_KEM(one_time_secret_key_responder->secret_key_KEM,
                        ciphertext_3, &shared_secret_3) < 0) {
        fprintf(stderr, "ERROR: decapsulation failed! \n");
        return 1;
    }

    // We hash the two shared secrets into two random seeds
    crypto_generichash_init(&hash_state, NULL, 0, HASH_LENGTH);
    crypto_generichash_update(
        &hash_state, (unsigned char *)shared_secret_1.shared_secret_content,
        crypto_box_BEFORENMBYTES);
    crypto_generichash_update(
        &hash_state, (unsigned char *)shared_secret_2.shared_secret_content,
        crypto_box_BEFORENMBYTES);
    crypto_generichash_update(
        &hash_state, (unsigned char *)shared_secret_3.shared_secret_content,
        crypto_box_BEFORENMBYTES);
    crypto_generichash_final(&hash_state, pre_key, HASH_LENGTH);

    crypto_kdf_derive_from_key(shared_key, sizeof shared_key, 1, CONTEXT,
                               pre_key);

    free_shared_secret_KEM(&shared_secret_1);
    free_shared_secret_KEM(&shared_secret_2);
    free_shared_secret_KEM(&shared_secret_3);

    return 0;
}

int terminate_protocol() {

    terminate_KEM();

    terminate_SIG();

    return 0;
}

void free_long_term_key_pair(long_term_secret_key *long_term_secret_key,
                             long_term_public_key *long_term_public_key) {

    free_key_pair_KEM(long_term_secret_key->secret_key_KEM,
                      long_term_public_key->public_key_KEM);
    free_key_pair_SIG(long_term_secret_key->secret_key_SIG,
                      long_term_public_key->public_key_SIG);
    free(long_term_public_key->public_key_KEM);
    free(long_term_public_key->public_key_SIG);
    free(long_term_secret_key->secret_key_KEM);
    free(long_term_secret_key->secret_key_SIG);

    return;
}

void free_static_key_pair(static_secret_key *static_secret_key,
                          static_public_key *static_public_key) {

    free_key_pair_KEM(static_secret_key->secret_key_KEM,
                      static_public_key->public_key_KEM);
    free_signature_SIG(static_public_key->signature);
    free(static_public_key->public_key_KEM);
    free(static_secret_key->secret_key_KEM);
    free(static_public_key->signature);

    return;
}

void free_one_time_key_pair(one_time_secret_key *one_time_secret_key,
                            one_time_public_key *one_time_public_key) {

    free_key_pair_KEM(one_time_secret_key->secret_key_KEM,
                      one_time_public_key->public_key_KEM);
    free(one_time_public_key->public_key_KEM);
    free(one_time_secret_key->secret_key_KEM);

    return;
}

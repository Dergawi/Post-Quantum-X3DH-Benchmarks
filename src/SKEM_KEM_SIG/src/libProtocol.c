#include "libProtocol.h"

#define CONTEXT "SKEM_SIG"

int initiate_protocol(const char *KEM_scheme_name,
                      const char *SIG_scheme_name) {

    instantiate_KEM(KEM_scheme_name);

    initiate_SKEM();

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

int one_time_key_gen(one_time_secret_key *one_time_secret_key,
                     long_term_secret_key *long_term_secret_key,
                     one_time_public_key *one_time_public_key) {

    one_time_public_key->public_key_SKEM = malloc(sizeof(public_key_SKEM));
    one_time_public_key->public_key_KEM = malloc(sizeof(public_key_KEM));
    one_time_public_key->signature = malloc(sizeof(signature));
    one_time_secret_key->secret_key_SKEM = malloc(sizeof(secret_key_SKEM));
    one_time_secret_key->secret_key_KEM = malloc(sizeof(secret_key_KEM));

    message message;

    if (key_gen_SKEM(one_time_secret_key->secret_key_SKEM,
                     one_time_public_key->public_key_SKEM) < 0) {
        fprintf(stderr, "ERROR: KEM key pair generation failed! \n");
        return 1;
    }

    if (key_gen_KEM(one_time_secret_key->secret_key_KEM,
                    one_time_public_key->public_key_KEM) < 0) {
        fprintf(stderr, "ERROR: KEM key pair generation failed! \n");
        return 1;
    }

    message.message_content =
        malloc(one_time_public_key->public_key_SKEM->public_key_length +
               one_time_public_key->public_key_KEM->public_key_length);
    void *q = message.message_content;
    memcpy(q, one_time_public_key->public_key_SKEM->public_key_content,
           one_time_public_key->public_key_SKEM->public_key_length);
    q = q + one_time_public_key->public_key_SKEM->public_key_length;
    memcpy(q, one_time_public_key->public_key_KEM->public_key_content,
           one_time_public_key->public_key_KEM->public_key_length);
    message.message_length =
        one_time_public_key->public_key_SKEM->public_key_length +
        one_time_public_key->public_key_KEM->public_key_length;

    if (sign_SIG(long_term_secret_key->secret_key_SIG, &message,
                 one_time_public_key->signature) < 0) {
        fprintf(stderr, "ERROR: SIG key pair generation failed! \n");
        return 2;
    }

    one_time_public_key->public_key_length =
        one_time_public_key->public_key_SKEM->public_key_length +
        one_time_public_key->public_key_KEM->public_key_length +
        one_time_public_key->signature->signature_length;
    one_time_secret_key->secret_key_length =
        one_time_secret_key->secret_key_SKEM->secret_key_length +
        one_time_secret_key->secret_key_KEM->secret_key_length;

    free_message(&message);

    return 0;
}

int initiator(one_time_secret_key *one_time_secret_key_initiator,
              one_time_public_key *one_time_public_key_initiator,
              long_term_public_key *long_term_public_key_responder,
              one_time_public_key *one_time_public_key_responder,
              ciphertext *ciphertext_1, ciphertext *ciphertext_2,
              ciphertext *ciphertext_3, size_t security_parameter) {

    uint8_t shared_key[security_parameter], pre_key[HASH_LENGTH];
    crypto_generichash_state hash_state;
    shared_secret shared_secret_1, shared_secret_2, shared_secret_3;
    message message;

    message.message_content = malloc(
        one_time_public_key_responder->public_key_SKEM->public_key_length +
        one_time_public_key_responder->public_key_KEM->public_key_length);
    void *q = message.message_content;
    memcpy(q,
           one_time_public_key_responder->public_key_SKEM->public_key_content,
           one_time_public_key_responder->public_key_SKEM->public_key_length);
    q = q + one_time_public_key_responder->public_key_SKEM->public_key_length;
    memcpy(q, one_time_public_key_responder->public_key_KEM->public_key_content,
           one_time_public_key_responder->public_key_KEM->public_key_length);
    message.message_length =
        one_time_public_key_responder->public_key_SKEM->public_key_length +
        one_time_public_key_responder->public_key_KEM->public_key_length;

    if (verify_SIG(long_term_public_key_responder->public_key_SIG, &message,
                   one_time_public_key_responder->signature)) {
        fprintf(stderr, "ERROR: SIG failed! \n");
        return 1;
    }
    /*
        if (key_gen_KEM(secret_key_KEM_3, public_key_KEM_3) < 0) {
            fprintf(stderr, "ERROR: KEM key pair generation failed! \n");
            return 2;
        }
    */
    if (encapsulate_KEM(long_term_public_key_responder->public_key_KEM,
                        ciphertext_1, &shared_secret_1) < 0) {
        fprintf(stderr, "ERROR: encapsulation failed! \n");
        return 3;
    }
    if (encapsulate_KEM(one_time_public_key_responder->public_key_KEM,
                        ciphertext_2, &shared_secret_2) < 0) {
        fprintf(stderr, "ERROR: encapsulation failed! \n");
        return 3;
    }
    if (encapsulate_SKEM(one_time_secret_key_initiator->secret_key_SKEM,
                         one_time_public_key_initiator->public_key_SKEM,
                         one_time_public_key_responder->public_key_SKEM,
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
    // crypto_generichash_update(&hash_state, (unsigned char*)
    // shared_secret_4.shared_secret_content, crypto_box_BEFORENMBYTES);
    crypto_generichash_final(&hash_state, pre_key, HASH_LENGTH);

    crypto_kdf_derive_from_key(shared_key, sizeof shared_key, 1, CONTEXT,
                               pre_key);

    free_message(&message);
    free_shared_secret_KEM(&shared_secret_1);
    free_shared_secret_KEM(&shared_secret_2);
    free_shared_secret_SKEM(&shared_secret_3);

    return 0;
}

int responder(long_term_secret_key *long_term_secret_key_responder,
              one_time_secret_key *one_time_secret_key_responder,
              one_time_public_key *one_time_public_key_initiator,
              one_time_public_key *one_time_public_key_responder,
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
    if (decapsulate_KEM(one_time_secret_key_responder->secret_key_KEM,
                        ciphertext_2, &shared_secret_2) < 0) {
        fprintf(stderr, "ERROR: decapsulation failed! \n");
        return 1;
    }
    if (decapsulate_SKEM(one_time_secret_key_responder->secret_key_SKEM,
                         one_time_public_key_responder->public_key_SKEM,
                         one_time_public_key_initiator->public_key_SKEM,
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
    // crypto_generichash_update(&hash_state, (unsigned char*)
    // shared_secret_4.shared_secret_content, crypto_box_BEFORENMBYTES);
    crypto_generichash_final(&hash_state, pre_key, HASH_LENGTH);

    crypto_kdf_derive_from_key(shared_key, sizeof shared_key, 1, CONTEXT,
                               pre_key);

    free_shared_secret_KEM(&shared_secret_1);
    free_shared_secret_KEM(&shared_secret_2);
    free_shared_secret_SKEM(&shared_secret_3);

    return 0;
}

int terminate_protocol() {

    terminate_KEM();

    terminate_SKEM();

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

void free_one_time_key_pair(one_time_secret_key *one_time_secret_key,
                            one_time_public_key *one_time_public_key) {

    free_key_pair_SKEM(one_time_secret_key->secret_key_SKEM,
                       one_time_public_key->public_key_SKEM);
    free_key_pair_KEM(one_time_secret_key->secret_key_KEM,
                      one_time_public_key->public_key_KEM);
    free_signature(one_time_public_key->signature);
    free(one_time_public_key->public_key_SKEM);
    free(one_time_public_key->public_key_KEM);
    free(one_time_secret_key->secret_key_SKEM);
    free(one_time_secret_key->secret_key_KEM);
    free(one_time_public_key->signature);

    return;
}

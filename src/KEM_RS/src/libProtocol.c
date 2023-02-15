#include "libProtocol.h"

int initiate_protocol(const char *KEM_scheme_name, const char *SIG_scheme_name) {

    instantiate_KEM(KEM_scheme_name);

    instantiate_SIG(SIG_scheme_name);

    initiate_RS();

    return 0;
}

int long_term_key_gen(long_term_secret_key *long_term_secret_key,
                      long_term_public_key *long_term_public_key) {

    long_term_public_key->public_key_KEM = malloc(sizeof(public_key_KEM));
    long_term_public_key->public_key_RS = malloc(sizeof(public_key_RS));
    long_term_public_key->public_key_SIG = malloc(sizeof(public_key_SIG));
    long_term_secret_key->secret_key_KEM = malloc(sizeof(secret_key_KEM));
    long_term_secret_key->secret_key_RS = malloc(sizeof(secret_key_RS));
    long_term_secret_key->secret_key_SIG = malloc(sizeof(secret_key_SIG));

    if (key_gen_KEM(long_term_secret_key->secret_key_KEM,
                    long_term_public_key->public_key_KEM) < 0) {
        fprintf(stderr, "ERROR: KEM key pair generation failed! \n");
        return 1;
    }

    if (key_gen_RS(long_term_secret_key->secret_key_RS,
                   long_term_public_key->public_key_RS) < 0) {
        fprintf(stderr, "ERROR: RS key pair generation failed! \n");
        return 2;
    }

    if (key_gen_SIG(long_term_secret_key->secret_key_SIG,
                    long_term_public_key->public_key_SIG) < 0) {
        fprintf(stderr, "ERROR: SIG key pair generation failed! \n");
        return 2;
    }

    long_term_public_key->public_key_length =
        long_term_public_key->public_key_KEM->public_key_length +
        long_term_public_key->public_key_RS->public_key_length +
        long_term_public_key->public_key_SIG->public_key_length;
    long_term_secret_key->secret_key_length =
        long_term_secret_key->secret_key_KEM->secret_key_length +
        long_term_secret_key->secret_key_RS->secret_key_length +
        long_term_secret_key->secret_key_SIG->secret_key_length;

    return 0;
}

int one_time_key_gen(one_time_secret_key *one_time_secret_key, long_term_secret_key *long_term_secret_key,
                     one_time_public_key *one_time_public_key) {

    message_SIG public_keys_signature;

    one_time_public_key->public_key_KEM = malloc(sizeof(public_key_KEM));
    one_time_public_key->public_key_RS = malloc(sizeof(public_key_RS));
    one_time_public_key->signature = malloc(sizeof(signature_SIG));
    one_time_secret_key->secret_key_KEM = malloc(sizeof(secret_key_KEM));
    one_time_secret_key->secret_key_RS = malloc(sizeof(secret_key_RS));

    if (key_gen_KEM(one_time_secret_key->secret_key_KEM,
                    one_time_public_key->public_key_KEM) < 0) {
        fprintf(stderr, "ERROR: KEM key pair generation failed! \n");
        return 1;
    }

    if (key_gen_RS(one_time_secret_key->secret_key_RS,
                   one_time_public_key->public_key_RS) < 0) {
        fprintf(stderr, "ERROR: RS key pair generation failed! \n");
        return 2;
    }

    public_keys_signature.message_length =
        one_time_public_key->public_key_KEM->public_key_length +
        one_time_public_key->public_key_RS->public_key_length;
    public_keys_signature.message_content =
        malloc(public_keys_signature.message_length);
    void *q = public_keys_signature.message_content;
    memcpy(q, one_time_public_key->public_key_KEM->public_key_content,
           one_time_public_key->public_key_KEM->public_key_length);
    q = q + one_time_public_key->public_key_KEM->public_key_length;
    memcpy(q, one_time_public_key->public_key_RS->public_key_content,
           one_time_public_key->public_key_RS->public_key_length);

    if (sign_SIG(long_term_secret_key->secret_key_SIG, &public_keys_signature,
                 one_time_public_key->signature) < 0) {
        fprintf(stderr, "ERROR: SIG key pair generation failed! \n");
        return 2;
    }

    one_time_public_key->public_key_length =
        one_time_public_key->public_key_KEM->public_key_length +
        one_time_public_key->public_key_RS->public_key_length +
        one_time_public_key->signature->signature_length;
    one_time_secret_key->secret_key_length =
        one_time_secret_key->secret_key_KEM->secret_key_length +
        one_time_secret_key->secret_key_RS->secret_key_length;

    free_message_SIG(&public_keys_signature);

    return 0;
}

int initiator(long_term_secret_key *long_term_secret_key_initiator,
              long_term_public_key *long_term_public_key_initiator,
              long_term_public_key *long_term_public_key_responder,
              one_time_public_key *one_time_public_key_responder,
              ciphertext *ciphertext_1, ciphertext *ciphertext_2,
              message *paded_signature, size_t security_parameter) {

    uint8_t shared_key[security_parameter];
    uint8_t random_seed_1[HASH_LENGTH], random_seed_2[HASH_LENGTH];
    uint8_t hash_digest_1[HASH_LENGTH], hash_digest_2[HASH_LENGTH];
    crypto_generichash_state hash_state_1, hash_state_2;
    message session_ID;
    signature session_ID_signature;
    shared_secret shared_secret_1, shared_secret_2;
    message_SIG public_keys_signature;

    public_keys_signature.message_length =
        one_time_public_key_responder->public_key_KEM->public_key_length +
        one_time_public_key_responder->public_key_RS->public_key_length;
    public_keys_signature.message_content =
        malloc(public_keys_signature.message_length);
    void *q = public_keys_signature.message_content;
    memcpy(q, one_time_public_key_responder->public_key_KEM->public_key_content,
           one_time_public_key_responder->public_key_KEM->public_key_length);
    q = q + one_time_public_key_responder->public_key_KEM->public_key_length;
    memcpy(q,
           one_time_public_key_responder->public_key_RS
               ->public_key_content,
           one_time_public_key_responder->public_key_RS
               ->public_key_length);

    if (verify_SIG(long_term_public_key_responder->public_key_SIG,
                   &public_keys_signature,
                   one_time_public_key_responder->signature)) {
        fprintf(stderr, "ERROR: SIG failed! \n");
        return 1;
    }

    if (encapsulate_KEM(long_term_public_key_responder->public_key_KEM,
                        ciphertext_1, &shared_secret_1) < 0) {
        fprintf(stderr, "ERROR: encapsulation failed! \n");
        return 1;
    }
    if (encapsulate_KEM(one_time_public_key_responder->public_key_KEM,
                        ciphertext_2, &shared_secret_2) < 0) {
        fprintf(stderr, "ERROR: encapsulation failed! \n");
        return 1;
    }

    // We hash the two shared secrets into two random seeds

    // The parameters NULL and 0 indicates that we don't use a key for the hash
    // function. It will be the case for all hash function of the library
    // "libsodium"
    crypto_generichash(random_seed_1, sizeof random_seed_1,
                       shared_secret_1.shared_secret_content,
                       shared_secret_1.shared_secret_length, NULL, 0);
    crypto_generichash(random_seed_2, sizeof random_seed_2,
                       shared_secret_2.shared_secret_content,
                       shared_secret_2.shared_secret_length, NULL, 0);

    // We evaluate and store the session ID in one continous memory segment
    session_ID.message_length =
        long_term_public_key_initiator->public_key_KEM->public_key_length +
        long_term_public_key_initiator->public_key_RS->public_key_length +
        long_term_public_key_responder->public_key_KEM->public_key_length +
        long_term_public_key_responder->public_key_RS->public_key_length +
        one_time_public_key_responder->public_key_RS->public_key_length +
        one_time_public_key_responder->public_key_KEM->public_key_length +
        ciphertext_1->ciphertext_length + ciphertext_2->ciphertext_length;
    session_ID.message_content = NULL;
    session_ID.message_content = malloc(session_ID.message_length);

    if (session_ID.message_content == NULL) {
        fprintf(stderr, "ERROR: malloc failed!\n");
        return 2;
    }

    uint8_t *p = session_ID.message_content;
    memcpy(p,
           long_term_public_key_initiator->public_key_KEM->public_key_content,
           long_term_public_key_initiator->public_key_KEM->public_key_length);
    p = p + long_term_public_key_initiator->public_key_KEM->public_key_length;
    memcpy(p, long_term_public_key_initiator->public_key_RS->public_key_content,
           long_term_public_key_initiator->public_key_RS->public_key_length);
    p = p + long_term_public_key_initiator->public_key_RS->public_key_length;
    memcpy(p,
           long_term_public_key_responder->public_key_KEM->public_key_content,
           long_term_public_key_responder->public_key_KEM->public_key_length);
    p = p + long_term_public_key_responder->public_key_KEM->public_key_length;
    memcpy(p, long_term_public_key_responder->public_key_RS->public_key_content,
           long_term_public_key_responder->public_key_RS->public_key_length);
    p = p + long_term_public_key_responder->public_key_RS->public_key_length;
    memcpy(p, one_time_public_key_responder->public_key_KEM->public_key_content,
           one_time_public_key_responder->public_key_KEM->public_key_length);
    p = p + one_time_public_key_responder->public_key_KEM->public_key_length;
    memcpy(p, one_time_public_key_responder->public_key_RS->public_key_content,
           one_time_public_key_responder->public_key_RS->public_key_length);
    p = p + one_time_public_key_responder->public_key_RS->public_key_length;
    memcpy(p, ciphertext_1->ciphertext_content,
           ciphertext_1->ciphertext_length);
    p = p + ciphertext_1->ciphertext_length;
    memcpy(p, ciphertext_2->ciphertext_content,
           ciphertext_2->ciphertext_length);
    p = p + ciphertext_2->ciphertext_length;

    // We hash the session ID with the random seeds to generate two hashes
    crypto_generichash_init(&hash_state_1, NULL, 0, HASH_LENGTH);
    crypto_generichash_update(&hash_state_1, random_seed_1,
                              sizeof random_seed_1);
    crypto_generichash_update(&hash_state_1, session_ID.message_content,
                              session_ID.message_length);
    crypto_generichash_final(&hash_state_1, hash_digest_1, HASH_LENGTH);

    crypto_generichash_init(&hash_state_2, NULL, 0, HASH_LENGTH);
    crypto_generichash_update(&hash_state_2, random_seed_2,
                              sizeof random_seed_2);
    crypto_generichash_update(&hash_state_2, session_ID.message_content,
                              session_ID.message_length);
    crypto_generichash_final(&hash_state_2, hash_digest_2, HASH_LENGTH);

    if (sign_RS(long_term_secret_key_initiator->secret_key_RS, &session_ID,
                long_term_public_key_initiator->public_key_RS,
                one_time_public_key_responder->public_key_RS,
                &session_ID_signature) < 0) {
        fprintf(stderr, "ERROR: signature failed! \n");
        free_message(&session_ID);
        free_signature(&session_ID_signature);
        return 3;
    }

    // We generate two random pads with the two hashes generated above
    uint8_t random_pad_1[session_ID_signature.signature_length +
                         security_parameter];
    uint8_t random_pad_2[session_ID_signature.signature_length +
                         security_parameter];
    randombytes_buf_deterministic(random_pad_1, sizeof random_pad_1,
                                  hash_digest_1);
    randombytes_buf_deterministic(random_pad_2, sizeof random_pad_2,
                                  hash_digest_2);

    // We XOR the two random pads to form one pad, the first part will be the
    // shared secret and the second part is a padding that will be used to hide
    // the signature
    uint8_t pad[session_ID_signature.signature_length];
    for (int i = 0; i < security_parameter; i++)
        shared_key[i] = random_pad_1[i] ^ random_pad_2[i];
    for (int i = security_parameter;
         i < session_ID_signature.signature_length + security_parameter; i++)
        pad[i - security_parameter] = random_pad_1[i] ^ random_pad_2[i];

    paded_signature->message_content = NULL;
    paded_signature->message_content =
        malloc(session_ID_signature.signature_length);
    paded_signature->message_length = session_ID_signature.signature_length;
    if (paded_signature->message_content == NULL) {
        fprintf(stderr, "ERROR: malloc failed!\n");
        free_message(&session_ID);
        free_signature(&session_ID_signature);
        return 2;
    }

    // We hide the signature by XORing it with the pad generated above
    for (int i = 0; i < paded_signature->message_length; i++)
        paded_signature->message_content[i] =
            ((uint8_t *)session_ID_signature.signature_content)[i] ^ pad[i];

    free_shared_secret_KEM(&shared_secret_1);
    free_shared_secret_KEM(&shared_secret_2);
    free_message_SIG(&public_keys_signature);
    free_message(&session_ID);
    free_signature(&session_ID_signature);

    return 0;
}

int responder(long_term_secret_key *long_term_secret_key_responder,
              one_time_secret_key *one_time_secret_key_responder,
              long_term_public_key *long_term_public_key_initiator,
              long_term_public_key *long_term_public_key_responder,
              one_time_public_key *one_time_public_key_responder,
              ciphertext *ciphertext_1, ciphertext *ciphertext_2,
              message *paded_signature, size_t security_parameter) {

    uint8_t random_seed_1[HASH_LENGTH], random_seed_2[HASH_LENGTH];
    uint8_t random_pad_1[paded_signature->message_length + security_parameter],
        random_pad_2[paded_signature->message_length + security_parameter];
    uint8_t hash_digest_1[HASH_LENGTH], hash_digest_2[HASH_LENGTH];
    uint8_t shared_key[security_parameter];
    uint8_t pad[paded_signature->message_length];
    crypto_generichash_state hash_state_1, hash_state_2;
    shared_secret shared_secret_1, shared_secret_2;
    signature session_ID_signature;
    message session_ID;

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

    // We hash the two shared secrets into two random seeds
    crypto_generichash(random_seed_1, sizeof random_seed_1,
                       shared_secret_1.shared_secret_content,
                       shared_secret_1.shared_secret_length, NULL, 0);
    crypto_generichash(random_seed_2, sizeof random_seed_2,
                       shared_secret_2.shared_secret_content,
                       shared_secret_2.shared_secret_length, NULL, 0);

    // We evaluate and store the session ID in one continous memory segment
    session_ID.message_length =
        long_term_public_key_initiator->public_key_KEM->public_key_length +
        long_term_public_key_initiator->public_key_RS->public_key_length +
        long_term_public_key_responder->public_key_KEM->public_key_length +
        long_term_public_key_responder->public_key_RS->public_key_length +
        one_time_public_key_responder->public_key_RS->public_key_length +
        one_time_public_key_responder->public_key_KEM->public_key_length +
        ciphertext_1->ciphertext_length + ciphertext_2->ciphertext_length;
    session_ID.message_content = NULL;
    session_ID.message_content = malloc(session_ID.message_length);

    if (session_ID.message_content == NULL) {
        fprintf(stderr, "ERROR: malloc failed!\n");
        return 2;
    }

    uint8_t *p = session_ID.message_content;
    memcpy(p,
           long_term_public_key_initiator->public_key_KEM->public_key_content,
           long_term_public_key_initiator->public_key_KEM->public_key_length);
    p = p + long_term_public_key_initiator->public_key_KEM->public_key_length;
    memcpy(p, long_term_public_key_initiator->public_key_RS->public_key_content,
           long_term_public_key_initiator->public_key_RS->public_key_length);
    p = p + long_term_public_key_initiator->public_key_RS->public_key_length;
    memcpy(p,
           long_term_public_key_responder->public_key_KEM->public_key_content,
           long_term_public_key_responder->public_key_KEM->public_key_length);
    p = p + long_term_public_key_responder->public_key_KEM->public_key_length;
    memcpy(p, long_term_public_key_responder->public_key_RS->public_key_content,
           long_term_public_key_responder->public_key_RS->public_key_length);
    p = p + long_term_public_key_responder->public_key_RS->public_key_length;
    memcpy(p, one_time_public_key_responder->public_key_KEM->public_key_content,
           one_time_public_key_responder->public_key_KEM->public_key_length);
    p = p + one_time_public_key_responder->public_key_KEM->public_key_length;
    memcpy(p, one_time_public_key_responder->public_key_RS->public_key_content,
           one_time_public_key_responder->public_key_RS->public_key_length);
    p = p + one_time_public_key_responder->public_key_RS->public_key_length;
    memcpy(p, ciphertext_1->ciphertext_content,
           ciphertext_1->ciphertext_length);
    p = p + ciphertext_1->ciphertext_length;
    memcpy(p, ciphertext_2->ciphertext_content,
           ciphertext_2->ciphertext_length);
    p = p + ciphertext_2->ciphertext_length;

    // We hash the session ID with the random seeds to generate two hashes
    crypto_generichash_init(&hash_state_1, NULL, 0, HASH_LENGTH);
    crypto_generichash_update(&hash_state_1, random_seed_1,
                              sizeof random_seed_1);
    crypto_generichash_update(&hash_state_1, session_ID.message_content,
                              session_ID.message_length);
    crypto_generichash_final(&hash_state_1, hash_digest_1, HASH_LENGTH);

    crypto_generichash_init(&hash_state_2, NULL, 0, HASH_LENGTH);
    crypto_generichash_update(&hash_state_2, random_seed_2,
                              sizeof random_seed_2);
    crypto_generichash_update(&hash_state_2, session_ID.message_content,
                              session_ID.message_length);
    crypto_generichash_final(&hash_state_2, hash_digest_2, HASH_LENGTH);

    // We generate two random pads with the two hashes generated above
    randombytes_buf_deterministic(random_pad_1, sizeof random_pad_1,
                                  hash_digest_1);
    randombytes_buf_deterministic(random_pad_2, sizeof random_pad_2,
                                  hash_digest_2);

    // We XOR the two random pads to form one pad, the first part will be the
    // shared secret and the second part is a padding that will be used to
    // uncover the signature
    for (int i = 0; i < security_parameter; i++)
        shared_key[i] = random_pad_1[i] ^ random_pad_2[i];
    for (int i = security_parameter;
         i < paded_signature->message_length + security_parameter; i++)
        pad[i - security_parameter] = random_pad_1[i] ^ random_pad_2[i];

    session_ID_signature.signature_content = NULL;
    session_ID_signature.signature_content =
        malloc(paded_signature->message_length);
    session_ID_signature.signature_length = paded_signature->message_length;

    // We uncover the signature by XORing it with the pad generated above
    for (int i = 0; i < paded_signature->message_length; i++)
        ((uint8_t *)session_ID_signature.signature_content)[i] =
            paded_signature->message_content[i] ^ pad[i];

    if (verify_RS(&session_ID_signature, &session_ID,
                  long_term_public_key_initiator->public_key_RS,
                  one_time_public_key_responder->public_key_RS) < 0) {
        fprintf(stderr, "ERROR: signature verification failed! \n");
        free_message(&session_ID);
        free_signature(&session_ID_signature);
        return 3;
    }

    free_shared_secret_KEM(&shared_secret_1);
    free_shared_secret_KEM(&shared_secret_2);
    free_message(&session_ID);
    free_signature(&session_ID_signature);

    return 0;
}

int terminate_protocol() {

    terminate_KEM();

    terminate_SIG();

    terminate_RS();

    return 0;
}

void free_long_term_key_pair(long_term_secret_key *long_term_secret_key,
                             long_term_public_key *long_term_public_key) {

    free_key_pair_KEM(long_term_secret_key->secret_key_KEM,
                      long_term_public_key->public_key_KEM);
    free_key_pair_RS(long_term_secret_key->secret_key_RS,
                     long_term_public_key->public_key_RS);
    free_key_pair_SIG(long_term_secret_key->secret_key_SIG,
                      long_term_public_key->public_key_SIG);
    free(long_term_public_key->public_key_KEM);
    free(long_term_public_key->public_key_RS);
    free(long_term_public_key->public_key_SIG);
    free(long_term_secret_key->secret_key_KEM);
    free(long_term_secret_key->secret_key_RS);
    free(long_term_secret_key->secret_key_SIG);

    return;
}

void free_one_time_key_pair(one_time_secret_key *one_time_secret_key,
                            one_time_public_key *one_time_public_key) {

    free_key_pair_KEM(one_time_secret_key->secret_key_KEM,
                      one_time_public_key->public_key_KEM);
    free_key_pair_RS(one_time_secret_key->secret_key_RS,
                     one_time_public_key->public_key_RS);
    free_signature_SIG(one_time_public_key->signature);
    free(one_time_public_key->public_key_KEM);
    free(one_time_public_key->public_key_RS);
    free(one_time_public_key->signature);
    free(one_time_secret_key->secret_key_KEM);
    free(one_time_secret_key->secret_key_RS);

    return;
}

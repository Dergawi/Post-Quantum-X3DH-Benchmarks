#include "libProtocol.h"

#define HASH_LENGTH 32
#define CONTEXT "KEM_DVS"

int initiate_protocol(const char *KEM_scheme_name,
                      const char *SIG_scheme_name) {

    instantiate_KEM(KEM_scheme_name);

    instantiate_SIG(SIG_scheme_name);

    initiate_DVS();

    return 0;
}

int long_term_key_gen(long_term_secret_key *long_term_secret_key,
                      long_term_public_key *long_term_public_key) {

    long_term_public_key->public_key_KEM = malloc(sizeof(public_key_KEM));
    long_term_public_key->public_key_signer_DVS =
        malloc(sizeof(public_key_signer_DVS));
    long_term_public_key->public_key_SIG = malloc(sizeof(public_key_SIG));
    long_term_secret_key->secret_key_KEM = malloc(sizeof(secret_key_KEM));
    long_term_secret_key->secret_key_signer_DVS =
        malloc(sizeof(secret_key_signer_DVS));
    long_term_secret_key->secret_key_SIG = malloc(sizeof(secret_key_SIG));

    if (key_gen_KEM(long_term_secret_key->secret_key_KEM,
                    long_term_public_key->public_key_KEM) < 0) {
        fprintf(stderr, "ERROR: long term key generation failed! \n");
        return 1;
    }

    if (key_gen_signer_DVS(long_term_secret_key->secret_key_signer_DVS,
                           long_term_public_key->public_key_signer_DVS) < 0) {
        fprintf(stderr, "ERROR: long term key generation failed! \n");
        return 2;
    }

    if (key_gen_SIG(long_term_secret_key->secret_key_SIG,
                    long_term_public_key->public_key_SIG) < 0) {
        fprintf(stderr, "ERROR: SIG key pair generation failed! \n");
        return 2;
    }

    long_term_public_key->public_key_length =
        long_term_public_key->public_key_KEM->public_key_length +
        long_term_public_key->public_key_signer_DVS->public_key_length +
        long_term_public_key->public_key_SIG->public_key_length;
    long_term_secret_key->secret_key_length =
        long_term_secret_key->secret_key_KEM->secret_key_length +
        long_term_secret_key->secret_key_signer_DVS->secret_key_length +
        long_term_secret_key->secret_key_SIG->secret_key_length;

    return 0;
}

int static_key_gen(static_secret_key *static_secret_key,
                   long_term_secret_key *long_term_secret_key,
                   static_public_key *static_public_key) {

    message_SIG public_keys_signature;

    static_public_key->public_key_KEM = malloc(sizeof(public_key_KEM));
    static_public_key->public_key_verifier_DVS =
        malloc(sizeof(public_key_verifier_DVS));
    static_public_key->signature = malloc(sizeof(signature_SIG));
    static_secret_key->secret_key_KEM = malloc(sizeof(secret_key_KEM));
    static_secret_key->secret_key_verifier_DVS =
        malloc(sizeof(secret_key_verifier_DVS));

    if (key_gen_KEM(static_secret_key->secret_key_KEM,
                    static_public_key->public_key_KEM) < 0) {
        fprintf(stderr, "ERROR: static key generation failed! \n");
        return 1;
    }

    if (key_gen_verifier_DVS(static_secret_key->secret_key_verifier_DVS,
                             static_public_key->public_key_verifier_DVS) < 0) {
        fprintf(stderr, "ERROR: static key generation failed! \n");
        return 2;
    }

    public_keys_signature.message_length =
        static_public_key->public_key_KEM->public_key_length +
        static_public_key->public_key_verifier_DVS->public_key_length;
    public_keys_signature.message_content =
        malloc(public_keys_signature.message_length);
    void *q = public_keys_signature.message_content;
    memcpy(q, static_public_key->public_key_KEM->public_key_content,
           static_public_key->public_key_KEM->public_key_length);
    q = q + static_public_key->public_key_KEM->public_key_length;
    memcpy(q, static_public_key->public_key_verifier_DVS->public_key_content,
           static_public_key->public_key_verifier_DVS->public_key_length);

    if (sign_SIG(long_term_secret_key->secret_key_SIG, &public_keys_signature,
                 static_public_key->signature) < 0) {
        fprintf(stderr, "ERROR: SIG key pair generation failed! \n");
        return 2;
    }

    static_public_key->public_key_length =
        static_public_key->public_key_KEM->public_key_length +
        static_public_key->public_key_verifier_DVS->public_key_length +
        static_public_key->signature->signature_length;
    static_secret_key->secret_key_length =
        static_secret_key->secret_key_KEM->secret_key_length +
        static_secret_key->secret_key_verifier_DVS->secret_key_length;

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

int initiator(long_term_secret_key *long_term_secret_key_initiator,
              long_term_public_key *long_term_public_key_initiator,
              long_term_public_key *long_term_public_key_responder,
              static_public_key *static_public_key_responder,
              one_time_public_key *one_time_public_key_responder,
              ciphertext *ciphertext_1, ciphertext *ciphertext_2,
              ciphertext *ciphertext_3, signature *session_ID_signature,
              message *nonce, size_t security_parameter) {

    int a = 0;
    int b = 1;
    unsigned char shared_key[((security_parameter / crypto_kdf_BYTES_MIN) + 1) *
                             crypto_kdf_BYTES_MIN];
    uint8_t key_KDF[HASH_LENGTH];
    crypto_generichash_state hash_state;
    message session_ID;
    shared_secret shared_secret_1, shared_secret_2, shared_secret_3;
    message_SIG public_keys_signature;

    public_keys_signature.message_length =
        static_public_key_responder->public_key_KEM->public_key_length +
        static_public_key_responder->public_key_verifier_DVS->public_key_length;
    public_keys_signature.message_content =
        malloc(public_keys_signature.message_length);
    void *q = public_keys_signature.message_content;
    memcpy(q, static_public_key_responder->public_key_KEM->public_key_content,
           static_public_key_responder->public_key_KEM->public_key_length);
    q = q + static_public_key_responder->public_key_KEM->public_key_length;
    memcpy(q,
           static_public_key_responder->public_key_verifier_DVS
               ->public_key_content,
           static_public_key_responder->public_key_verifier_DVS
               ->public_key_length);

    if (verify_SIG(long_term_public_key_responder->public_key_SIG,
                   &public_keys_signature,
                   static_public_key_responder->signature)) {
        fprintf(stderr, "ERROR: SIG failed! \n");
        return 1;
    }

    nonce->message_length = security_parameter;
    nonce->message_content = NULL;
    nonce->message_content = malloc(nonce->message_length);
    if (nonce->message_content == NULL) {
        fprintf(stderr, "ERROR: malloc failed!\n");
        return 1;
    }
    randombytes_buf(nonce->message_content, nonce->message_length);

    if (encapsulate_KEM(long_term_public_key_responder->public_key_KEM,
                        ciphertext_1, &shared_secret_1) < 0) {
        fprintf(stderr, "ERROR: initiator failed! \n");
        return 2;
    }
    if (encapsulate_KEM(static_public_key_responder->public_key_KEM,
                        ciphertext_2, &shared_secret_2) < 0) {
        fprintf(stderr, "ERROR: initiator failed! \n");
        return 2;
    }
    if (encapsulate_KEM(one_time_public_key_responder->public_key_KEM,
                        ciphertext_3, &shared_secret_3) < 0) {
        fprintf(stderr, "ERROR: initiator failed! \n");
        return 2;
    }

    session_ID.message_length =
        long_term_public_key_initiator->public_key_KEM->public_key_length +
        long_term_public_key_initiator->public_key_signer_DVS
            ->public_key_length +
        long_term_public_key_responder->public_key_KEM->public_key_length +
        long_term_public_key_responder->public_key_signer_DVS
            ->public_key_length +
        static_public_key_responder->public_key_KEM->public_key_length +
        static_public_key_responder->public_key_verifier_DVS
            ->public_key_length +
        nonce->message_length + ciphertext_1->ciphertext_length +
        ciphertext_2->ciphertext_length + ciphertext_3->ciphertext_length;
    session_ID.message_content = NULL;
    session_ID.message_content = malloc(session_ID.message_length);
    if (session_ID.message_content == NULL) {
        fprintf(stderr, "ERROR: malloc failed!\n");
        return 1;
    }

    // Here we store the session ID in one continous memory segment
    uint8_t *p = session_ID.message_content;
    memcpy(p,
           long_term_public_key_initiator->public_key_KEM->public_key_content,
           long_term_public_key_initiator->public_key_KEM->public_key_length);
    p = p + long_term_public_key_initiator->public_key_KEM->public_key_length;
    memcpy(p,
           long_term_public_key_initiator->public_key_signer_DVS
               ->public_key_content,
           long_term_public_key_initiator->public_key_signer_DVS
               ->public_key_length);
    p = p + long_term_public_key_initiator->public_key_signer_DVS
                ->public_key_length;
    memcpy(p,
           long_term_public_key_responder->public_key_KEM->public_key_content,
           long_term_public_key_responder->public_key_KEM->public_key_length);
    p = p + long_term_public_key_responder->public_key_KEM->public_key_length;
    memcpy(p,
           long_term_public_key_responder->public_key_signer_DVS
               ->public_key_content,
           long_term_public_key_responder->public_key_signer_DVS
               ->public_key_length);
    p = p + long_term_public_key_responder->public_key_signer_DVS
                ->public_key_length;
    memcpy(p, static_public_key_responder->public_key_KEM->public_key_content,
           static_public_key_responder->public_key_KEM->public_key_length);
    p = p + static_public_key_responder->public_key_KEM->public_key_length;
    memcpy(p,
           static_public_key_responder->public_key_verifier_DVS
               ->public_key_content,
           static_public_key_responder->public_key_verifier_DVS
               ->public_key_length);
    p = p +
        static_public_key_responder->public_key_verifier_DVS->public_key_length;
    memcpy(p, nonce->message_content, nonce->message_length);
    p = p + nonce->message_length;
    memcpy(p, ciphertext_1->ciphertext_content,
           ciphertext_1->ciphertext_length);
    p = p + ciphertext_1->ciphertext_length;
    memcpy(p, ciphertext_2->ciphertext_content,
           ciphertext_2->ciphertext_length);
    p = p + ciphertext_2->ciphertext_length;
    memcpy(p, ciphertext_3->ciphertext_content,
           ciphertext_3->ciphertext_length);
    p = p + ciphertext_3->ciphertext_length;

    // The parameters NULL and 0 indicates that we don't use a key for the hash
    // function. It will be the case for all hash function of the library
    // "libsodium"
    crypto_generichash_init(&hash_state, NULL, 0, HASH_LENGTH);
    crypto_generichash_update(&hash_state,
                              shared_secret_1.shared_secret_content,
                              shared_secret_1.shared_secret_length);
    crypto_generichash_update(&hash_state,
                              shared_secret_2.shared_secret_content,
                              shared_secret_2.shared_secret_length);
    crypto_generichash_update(&hash_state,
                              shared_secret_3.shared_secret_content,
                              shared_secret_3.shared_secret_length);
    crypto_generichash_update(&hash_state, session_ID.message_content,
                              session_ID.message_length);
    crypto_generichash_final(&hash_state, key_KDF, HASH_LENGTH);

    if (sign_DVS(long_term_secret_key_initiator->secret_key_signer_DVS,
                 &session_ID,
                 long_term_public_key_initiator->public_key_signer_DVS,
                 static_public_key_responder->public_key_verifier_DVS,
                 session_ID_signature) < 0) {
        fprintf(stderr, "ERROR: initiator failed! \n");
        return 1;
    }

    while (a < security_parameter + crypto_kdf_BYTES_MIN) {
        crypto_kdf_derive_from_key(shared_key + a, crypto_kdf_BYTES_MIN, b,
                                   CONTEXT, key_KDF);
        a = a + crypto_kdf_BYTES_MIN;
        b++;
    }

    free_shared_secret_KEM(&shared_secret_1);
    free_shared_secret_KEM(&shared_secret_2);
    free_shared_secret_KEM(&shared_secret_3);
    free_message_SIG(&public_keys_signature);
    free_message(&session_ID);

    return 0;
}

int responder(long_term_secret_key *long_term_secret_key_responder,
              static_secret_key *static_secret_key_responder,
              one_time_secret_key *one_time_secret_key_responder,
              long_term_public_key *long_term_public_key_initiator,
              long_term_public_key *long_term_public_key_responder,
              static_public_key *static_public_key_responder,
              ciphertext *ciphertext_1, ciphertext *ciphertext_2,
              ciphertext *ciphertext_3, signature *session_ID_signature,
              message *nonce, size_t security_parameter) {

    int a = 0;
    int b = 1;
    unsigned char shared_key[((security_parameter / crypto_kdf_BYTES_MIN) + 1) *
                             crypto_kdf_BYTES_MIN];
    uint8_t key_KDF[HASH_LENGTH];
    crypto_generichash_state hash_state;
    message session_ID;
    shared_secret shared_secret_1, shared_secret_2, shared_secret_3;

    session_ID.message_length =
        long_term_public_key_initiator->public_key_KEM->public_key_length +
        long_term_public_key_initiator->public_key_signer_DVS
            ->public_key_length +
        long_term_public_key_responder->public_key_KEM->public_key_length +
        long_term_public_key_responder->public_key_signer_DVS
            ->public_key_length +
        static_public_key_responder->public_key_KEM->public_key_length +
        static_public_key_responder->public_key_verifier_DVS
            ->public_key_length +
        nonce->message_length + ciphertext_1->ciphertext_length +
        ciphertext_2->ciphertext_length + ciphertext_3->ciphertext_length;
    session_ID.message_content = NULL;
    session_ID.message_content = malloc(session_ID.message_length);
    if (session_ID.message_content == NULL) {
        fprintf(stderr, "ERROR: malloc failed!\n");
        return 1;
    }

    // Here we store the session ID in one continous memory segment
    uint8_t *p = session_ID.message_content;
    memcpy(p,
           long_term_public_key_initiator->public_key_KEM->public_key_content,
           long_term_public_key_initiator->public_key_KEM->public_key_length);
    p = p + long_term_public_key_initiator->public_key_KEM->public_key_length;
    memcpy(p,
           long_term_public_key_initiator->public_key_signer_DVS
               ->public_key_content,
           long_term_public_key_initiator->public_key_signer_DVS
               ->public_key_length);
    p = p + long_term_public_key_initiator->public_key_signer_DVS
                ->public_key_length;
    memcpy(p,
           long_term_public_key_responder->public_key_KEM->public_key_content,
           long_term_public_key_responder->public_key_KEM->public_key_length);
    p = p + long_term_public_key_responder->public_key_KEM->public_key_length;
    memcpy(p,
           long_term_public_key_responder->public_key_signer_DVS
               ->public_key_content,
           long_term_public_key_responder->public_key_signer_DVS
               ->public_key_length);
    p = p + long_term_public_key_responder->public_key_signer_DVS
                ->public_key_length;
    memcpy(p, static_public_key_responder->public_key_KEM->public_key_content,
           static_public_key_responder->public_key_KEM->public_key_length);
    p = p + static_public_key_responder->public_key_KEM->public_key_length;
    memcpy(p,
           static_public_key_responder->public_key_verifier_DVS
               ->public_key_content,
           static_public_key_responder->public_key_verifier_DVS
               ->public_key_length);
    p = p +
        static_public_key_responder->public_key_verifier_DVS->public_key_length;
    memcpy(p, nonce->message_content, nonce->message_length);
    p = p + nonce->message_length;
    memcpy(p, ciphertext_1->ciphertext_content,
           ciphertext_1->ciphertext_length);
    p = p + ciphertext_1->ciphertext_length;
    memcpy(p, ciphertext_2->ciphertext_content,
           ciphertext_2->ciphertext_length);
    p = p + ciphertext_2->ciphertext_length;
    memcpy(p, ciphertext_3->ciphertext_content,
           ciphertext_3->ciphertext_length);
    p = p + ciphertext_3->ciphertext_length;

    if (verify_DVS(session_ID_signature, &session_ID,
                   long_term_public_key_initiator->public_key_signer_DVS,
                   static_public_key_responder->public_key_verifier_DVS) < 0) {
        fprintf(stderr, "ERROR: responder failed! \n");
        return 2;
    }

    if (decapsulate_KEM(long_term_secret_key_responder->secret_key_KEM,
                        ciphertext_1, &shared_secret_1) < 0) {
        fprintf(stderr, "ERROR: responder failed! \n");
        return 3;
    }
    if (decapsulate_KEM(static_secret_key_responder->secret_key_KEM,
                        ciphertext_2, &shared_secret_2) < 0) {
        fprintf(stderr, "ERROR: responder failed! \n");
        return 3;
    }
    if (decapsulate_KEM(one_time_secret_key_responder->secret_key_KEM,
                        ciphertext_3, &shared_secret_3) < 0) {
        fprintf(stderr, "ERROR: responder failed! \n");
        return 3;
    }

    crypto_generichash_init(&hash_state, NULL, 0, HASH_LENGTH);
    crypto_generichash_update(&hash_state,
                              shared_secret_1.shared_secret_content,
                              shared_secret_1.shared_secret_length);
    crypto_generichash_update(&hash_state,
                              shared_secret_2.shared_secret_content,
                              shared_secret_2.shared_secret_length);
    crypto_generichash_update(&hash_state,
                              shared_secret_3.shared_secret_content,
                              shared_secret_3.shared_secret_length);
    crypto_generichash_update(&hash_state, session_ID.message_content,
                              session_ID.message_length);
    crypto_generichash_final(&hash_state, key_KDF, HASH_LENGTH);

    while (a < security_parameter + crypto_kdf_BYTES_MIN) {
        crypto_kdf_derive_from_key(shared_key + a, crypto_kdf_BYTES_MIN, b,
                                   CONTEXT, key_KDF);
        a = a + crypto_kdf_BYTES_MIN;
        b++;
    }

    free_shared_secret_KEM(&shared_secret_1);
    free_shared_secret_KEM(&shared_secret_2);
    free_shared_secret_KEM(&shared_secret_3);
    free_message(&session_ID);

    return 0;
}

int terminate_protocol() {

    terminate_KEM();

    terminate_SIG();

    terminate_DVS();

    return 0;
}

void free_long_term_key_pair(long_term_secret_key *long_term_secret_key,
                             long_term_public_key *long_term_public_key) {

    free_key_pair_KEM(long_term_secret_key->secret_key_KEM,
                      long_term_public_key->public_key_KEM);
    free_key_pair_signer_DVS(long_term_secret_key->secret_key_signer_DVS,
                             long_term_public_key->public_key_signer_DVS);
    free_key_pair_SIG(long_term_secret_key->secret_key_SIG,
                      long_term_public_key->public_key_SIG);
    free(long_term_public_key->public_key_KEM);
    free(long_term_public_key->public_key_signer_DVS);
    free(long_term_public_key->public_key_SIG);
    free(long_term_secret_key->secret_key_KEM);
    free(long_term_secret_key->secret_key_signer_DVS);
    free(long_term_secret_key->secret_key_SIG);

    return;
}

void free_static_key_pair(static_secret_key *static_secret_key,
                          static_public_key *static_public_key) {

    free_key_pair_KEM(static_secret_key->secret_key_KEM,
                      static_public_key->public_key_KEM);
    free_key_pair_verifier_DVS(static_secret_key->secret_key_verifier_DVS,
                               static_public_key->public_key_verifier_DVS);
    free_signature_SIG(static_public_key->signature);
    free(static_public_key->public_key_KEM);
    free(static_public_key->public_key_verifier_DVS);
    free(static_public_key->signature);
    free(static_secret_key->secret_key_KEM);
    free(static_secret_key->secret_key_verifier_DVS);

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

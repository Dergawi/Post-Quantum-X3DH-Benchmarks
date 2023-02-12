#include <sodium.h>
#include <string.h>

#include "../../libs/libDVS/include/header_DVS.h"
#include "../../libs/libKEM/include/header_KEM.h"

typedef struct long_term_public_key {
    public_key_KEM *public_key_KEM;
    public_key_signer_DVS *public_key_signer_DVS;
    size_t public_key_length;
} long_term_public_key;

typedef struct long_term_secret_key {
    secret_key_KEM *secret_key_KEM;
    secret_key_signer_DVS *secret_key_signer_DVS;
    size_t secret_key_length;
} long_term_secret_key;

typedef struct static_public_key {
    public_key_KEM *public_key_KEM;
    public_key_verifier_DVS *public_key_verifier_DVS;
    size_t public_key_length;
} static_public_key;

typedef struct static_secret_key {
    secret_key_KEM *secret_key_KEM;
    secret_key_verifier_DVS *secret_key_verifier_DVS;
    size_t secret_key_length;
} static_secret_key;

typedef struct one_time_public_key {
    public_key_KEM *public_key_KEM;
    size_t public_key_length;
} one_time_public_key;

typedef struct one_time_secret_key {
    secret_key_KEM *secret_key_KEM;
    size_t secret_key_length;
} one_time_secret_key;

int initiate_protocol(const char *KEM_scheme_name);

int long_term_key_gen(long_term_secret_key *long_term_secret_key,
                      long_term_public_key *long_term_public_key);

int static_key_gen(static_secret_key *static_secret_key,
                   static_public_key *static_public_key);

int one_time_key_gen(one_time_secret_key *one_time_secret_key,
                     one_time_public_key *one_time_public_key);

int initiator(long_term_secret_key *long_term_secret_key_initiator,
              long_term_public_key *long_term_public_key_initiator,
              long_term_public_key *long_term_public_key_responder,
              static_public_key *static_public_key_responder,
              one_time_public_key *one_time_public_key_responder,
              ciphertext *ciphertext_1, ciphertext *ciphertext_2,
              ciphertext *ciphertext_3, signature *session_ID_signature,
              message *nonce, size_t security_parameter);

int responder(long_term_secret_key *long_term_secret_key_responder,
              static_secret_key *static_secret_key_responder,
              one_time_secret_key *one_time_secret_key_responder,
              long_term_public_key *long_term_public_key_initiator,
              long_term_public_key *long_term_public_key_responder,
              static_public_key *static_public_key_responder,
              ciphertext *ciphertext_1, ciphertext *ciphertext_2,
              ciphertext *ciphertext_3, signature *session_ID_signature,
              message *nonce, size_t security_parameter);

int terminate_protocol();

void free_long_term_key_pair(long_term_secret_key *long_term_secret_key,
                             long_term_public_key *long_term_public_key);

void free_static_key_pair(static_secret_key *static_secret_key,
                          static_public_key *static_public_key);

void free_one_time_key_pair(one_time_secret_key *one_time_secret_key,
                            one_time_public_key *one_time_public_key);

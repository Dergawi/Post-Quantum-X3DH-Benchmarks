#include <sodium.h>
#include <string.h>

#include "../../libs/libKEM/include/header_KEM.h"
#include "../../libs/libRS/include/header_RS.h"
#include "../../libs/libSIG/include/header_SIG.h"

#define HASH_LENGTH 32

typedef struct long_term_public_key {
    public_key_KEM *public_key_KEM;
    public_key_RS *public_key_RS;
    public_key_SIG *public_key_SIG;
    size_t public_key_length;
} long_term_public_key;

typedef struct long_term_secret_key {
    secret_key_KEM *secret_key_KEM;
    secret_key_RS *secret_key_RS;
    secret_key_SIG *secret_key_SIG;
    size_t secret_key_length;
} long_term_secret_key;

// There is no static key in this scheme

typedef struct one_time_public_key {
    public_key_KEM *public_key_KEM;
    public_key_RS *public_key_RS;
    signature_SIG *signature;
    size_t public_key_length;
} one_time_public_key;

typedef struct one_time_secret_key {
    secret_key_KEM *secret_key_KEM;
    secret_key_RS *secret_key_RS;
    size_t secret_key_length;
} one_time_secret_key;

int initiate_protocol(const char *KEM_scheme_name, const char *SIG_scheme_name);

int long_term_key_gen(long_term_secret_key *long_term_secret_key,
                      long_term_public_key *long_term_public_key);

int one_time_key_gen(one_time_secret_key *one_time_secret_key,
                     long_term_secret_key *long_term_secret_key,
                     one_time_public_key *one_time_public_key);

int initiator(long_term_secret_key *long_term_secret_key_initiator,
              long_term_public_key *long_term_public_key_initiator,
              long_term_public_key *long_term_public_key_responder,
              one_time_public_key *one_time_public_key_responder,
              ciphertext *ciphertext_1, ciphertext *ciphertext_2,
              message *paded_signature, size_t security_parameter);

int responder(long_term_secret_key *long_term_secret_key_responder,
              one_time_secret_key *one_time_secret_key_responder,
              long_term_public_key *long_term_public_key_initiator,
              long_term_public_key *long_term_public_key_responder,
              one_time_public_key *one_time_public_key_responder,
              ciphertext *ciphertext_1, ciphertext *ciphertext_2,
              message *paded_signature, size_t security_parameter);

int terminate_protocol();

void free_long_term_key_pair(long_term_secret_key *long_term_secret_key,
                             long_term_public_key *long_term_public_key);

void free_one_time_key_pair(one_time_secret_key *one_time_secret_key,
                            one_time_public_key *one_time_public_key);

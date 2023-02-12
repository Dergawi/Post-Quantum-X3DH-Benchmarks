#include <sodium.h>

typedef struct public_key_DH {
    void *public_key_content;
    size_t public_key_length;
} public_key_DH;

typedef struct secret_key_DH {
    void *secret_key_content;
    size_t secret_key_length;
} secret_key_DH;

typedef struct signature {
    void *signature_content;
    size_t signature_length;
} signature;

int initiate_protocol();

int long_term_key_gen(secret_key_DH *secret_key_DH,
                      public_key_DH *public_key_DH);

int static_key_gen(secret_key_DH *long_term_secret_key_DH,
                   secret_key_DH *static_secret_key_DH,
                   public_key_DH *static_public_key_DH, signature *signature);

int one_time_key_gen(secret_key_DH *secret_key_DH,
                     public_key_DH *public_key_DH);

int initiator(secret_key_DH *long_term_secret_key_DH_initiator,
              public_key_DH *long_term_public_key_DH_responder,
              public_key_DH *static_public_key_DH,
              public_key_DH *one_time_public_key_DH,
              secret_key_DH *ephemeral_secret_key_DH,
              public_key_DH *ephemeral_public_key_DH, signature *signature);

int responder(public_key_DH *long_term_public_key_DH_initiator,
              secret_key_DH *long_term_secret_key_DH_responder,
              secret_key_DH *static_secret_key_DH,
              secret_key_DH *one_time_secret_key_DH,
              public_key_DH *ephemeral_public_key_DH);

void free_key_pair(secret_key_DH *secret_key_DH, public_key_DH *public_key_DH);

void free_signature(signature *signature);
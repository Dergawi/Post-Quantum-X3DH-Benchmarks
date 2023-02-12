#include <stdio.h>

typedef struct public_key_RS {
    void *public_key_content;
    size_t public_key_length;
} public_key_RS;

typedef struct secret_key_RS {
    void *secret_key_content;
    size_t secret_key_length;
} secret_key_RS;

typedef struct message {
    unsigned char *message_content;
    size_t message_length;
} message;

typedef struct signature {
    void *signature_content;
    size_t signature_length;
} signature;

int initiate_RS();

int key_gen_RS(secret_key_RS *secret_key_RS, public_key_RS *public_key_RS);

int sign_RS(secret_key_RS *secret_key_signer, message *message,
            public_key_RS *public_key_signer,
            public_key_RS *public_key_verifier, signature *signature);

int verify_RS(signature *signature, message *message,
              public_key_RS *public_key_signer,
              public_key_RS *public_key_verifier);

int terminate_RS();

void free_key_pair_RS(secret_key_RS *secret_key_RS,
                      public_key_RS *public_key_RS);

void free_message(message *message);

void free_signature(signature *signature);

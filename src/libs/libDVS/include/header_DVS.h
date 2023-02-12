#include <stdio.h>

typedef struct public_key_signer_DVS {
    void *public_key_content;
    size_t public_key_length;
} public_key_signer_DVS;

typedef struct secret_key_signer_DVS {
    void *secret_key_content;
    size_t secret_key_length;
} secret_key_signer_DVS;

typedef struct public_key_verifier_DVS {
    void *public_key_content;
    size_t public_key_length;
} public_key_verifier_DVS;

typedef struct secret_key_verifier_DVS {
    void *secret_key_content;
    size_t secret_key_length;
} secret_key_verifier_DVS;

typedef struct message {
    unsigned char *message_content;
    unsigned long long message_length;
} message;

typedef struct signature {
    void *signature_content;
    unsigned long long signature_length;
} signature;

int initiate_DVS();

int key_gen_signer_DVS(secret_key_signer_DVS *secret_key_signer_DVS,
                       public_key_signer_DVS *public_key_signer_DVS);

int key_gen_verifier_DVS(secret_key_verifier_DVS *secret_key_verifier_DVS,
                         public_key_verifier_DVS *public_key_verifier_DVS);

int sign_DVS(secret_key_signer_DVS *secret_key_signer_DVS, message *message,
             public_key_signer_DVS *public_key_signer_DVS,
             public_key_verifier_DVS *public_key_verifier_DVS,
             signature *signature);

int simulate_DVS(secret_key_verifier_DVS *secret_key_verifier_DVS,
                 message *message, public_key_signer_DVS *public_key_signer_DVS,
                 public_key_verifier_DVS *public_key_verifier_DVS,
                 signature *signature);

int verify_DVS(signature *signature, message *message,
               public_key_signer_DVS *public_key_signer_DVS,
               public_key_verifier_DVS *public_key_verifier_DVS);

int terminate_DVS();

void free_key_pair_signer_DVS(secret_key_signer_DVS *secret_key_signer_DVS,
                              public_key_signer_DVS *public_key_signer_DVS);

void free_key_pair_verifier_DVS(
    secret_key_verifier_DVS *secret_key_verifier_DVS,
    public_key_verifier_DVS *public_key_verifier_DVS);

void free_message(message *message);

void free_signature(signature *signature);

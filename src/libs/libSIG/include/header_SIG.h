#include <stdio.h>

typedef struct public_key_SIG {
    void *public_key_content;
    size_t public_key_length;
} public_key_SIG;

typedef struct secret_key_SIG {
    void *secret_key_content;
    size_t secret_key_length;
} secret_key_SIG;

typedef struct message_SIG {
    unsigned char *message_content;
    size_t message_length;
} message_SIG;

typedef struct signature_SIG {
    void *signature_content;
    size_t signature_length;
} signature_SIG;

int get_number_of_SIG();

const char *get_name_SIG(int index);

int get_NIST_security_level_SIG(const char *SIG_scheme_name);

int instantiate_SIG(const char *SIG_scheme_name);

int key_gen_SIG(secret_key_SIG *secret_key_SIG, public_key_SIG *public_key_SIG);

int sign_SIG(secret_key_SIG *secret_key_SIG, message_SIG *message,
             signature_SIG *signature);

int verify_SIG(public_key_SIG *public_key_SIG, message_SIG *message,
               signature_SIG *signature);

int terminate_SIG();

void free_key_pair_SIG(secret_key_SIG *secret_key_SIG,
                       public_key_SIG *public_key_SIG);

void free_message_SIG(message_SIG *message);

void free_signature_SIG(signature_SIG *signature);

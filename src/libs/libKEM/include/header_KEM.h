#include <stdio.h>

typedef struct public_key_KEM {
    void *public_key_content;
    size_t public_key_length;
} public_key_KEM;

typedef struct secret_key_KEM {
    void *secret_key_content;
    size_t secret_key_length;
} secret_key_KEM;

#ifndef KEM_structure
#define KEM_structure

typedef struct ciphertext {
    void *ciphertext_content;
    size_t ciphertext_length;
} ciphertext;

typedef struct shared_secret {
    void *shared_secret_content;
    size_t shared_secret_length;
} shared_secret;

#endif

int get_number_of_KEM();

const char *get_name_KEM(int index);

int get_NIST_security_level_KEM(const char *KEM_scheme_name);

int instantiate_KEM(const char *KEM_scheme_name);

int key_gen_KEM(secret_key_KEM *secret_key_KEM, public_key_KEM *public_key_KEM);

int encapsulate_KEM(public_key_KEM *public_key_KEM, ciphertext *ciphertext,
                    shared_secret *shared_secret);

int decapsulate_KEM(secret_key_KEM *secret_key_KEM, ciphertext *ciphertext_KEM,
                    shared_secret *shared_secret);

int terminate_KEM();

void free_key_pair_KEM(secret_key_KEM *secret_key_KEM,
                       public_key_KEM *public_key_KEM);

void free_ciphertext_KEM(ciphertext *ciphertext);

void free_shared_secret_KEM(shared_secret *shared_secret);


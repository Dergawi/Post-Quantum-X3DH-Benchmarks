#include <stdio.h>

typedef struct public_key_SKEM {
    void *public_key_content;
    size_t public_key_length;
} public_key_SKEM;

typedef struct secret_key_SKEM {
    void *secret_key_content;
    size_t secret_key_length;
} secret_key_SKEM;

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

int initiate_SKEM();

int key_gen_SKEM(secret_key_SKEM *secret_key_SKEM,
                 public_key_SKEM *public_key_SKEM);

int encapsulate_SKEM(secret_key_SKEM *secret_key_encapsulator_SKEM,
                     public_key_SKEM *public_key_encapsulator_SKEM,
                     public_key_SKEM *public_key_decapsulator_SKEM,
                     ciphertext *ciphertext, shared_secret *shared_secret);

int decapsulate_SKEM(secret_key_SKEM *secret_key_decapsulator_SKEM,
                     public_key_SKEM *public_key_decapsulator_SKEM,
                     public_key_SKEM *public_key_encapsulator_SKEM,
                     ciphertext *ciphertext, shared_secret *shared_secret);

int terminate_SKEM();

void free_key_pair_SKEM(secret_key_SKEM *secret_key_SKEM,
                        public_key_SKEM *public_key_SKEM);
                        
void free_ciphertext_SKEM(ciphertext *ciphertext);

void free_shared_secret_SKEM(shared_secret *shared_secret);


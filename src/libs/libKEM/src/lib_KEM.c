#include <oqs/oqs.h>
#include <stdio.h>

#include "../include/header_KEM.h"

#define NUMBER_NIST_FINALIST_KEM 2

OQS_KEM *KEM_scheme;

char *name_nist_finalist_full_list_kem[6] = {"Kyber512", "Kyber768", "Kyber1024", "Kyber512-90s", "Kyber768-90s", "Kyber1024-90s"};

char *name_nist_finalist_kem[NUMBER_NIST_FINALIST_KEM] = {"Kyber512", "Kyber512-90s"};

int get_number_of_KEM() { return NUMBER_NIST_FINALIST_KEM; }

const char *get_name_KEM(int index) { return name_nist_finalist_kem[index]; }

int get_NIST_security_level_KEM(const char *KEM_scheme_name) {

    OQS_KEM *instance_tmp = OQS_KEM_new(KEM_scheme_name);

    int result = instance_tmp->claimed_nist_level;

    OQS_KEM_free(instance_tmp);

    return result;
}

int instantiate_KEM(const char *KEM_scheme_name) {

    int i = 0;

    KEM_scheme = NULL;

    KEM_scheme = OQS_KEM_new(KEM_scheme_name);

    if (KEM_scheme == NULL) {
        fprintf(stderr, "ERROR: ");
        while (KEM_scheme_name[i] != '\0') {
            fprintf(stderr, "%c", KEM_scheme_name[i]);
            ++i;
        }
        fprintf(stderr, " was not enabled at compile-time.\n");
        return 1;
    }

    return 0;
}

int key_gen_KEM(secret_key_KEM *secret_key_KEM,
                public_key_KEM *public_key_KEM) {

    public_key_KEM->public_key_content = NULL;
    secret_key_KEM->secret_key_content = NULL;

    public_key_KEM->public_key_content = malloc(KEM_scheme->length_public_key);
    secret_key_KEM->secret_key_content = malloc(KEM_scheme->length_secret_key);

    if ((public_key_KEM->public_key_content == NULL) ||
        (secret_key_KEM->secret_key_content == NULL)) {
        fprintf(stderr, "ERROR: malloc failed!\n");
        return 1;
    }

    OQS_STATUS rc =
        OQS_KEM_keypair(KEM_scheme, public_key_KEM->public_key_content,
                        secret_key_KEM->secret_key_content);

    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: key_gen_KEM failed!\n");
        return 2;
    }

    public_key_KEM->public_key_length = KEM_scheme->length_public_key;
    secret_key_KEM->secret_key_length = KEM_scheme->length_secret_key;

    return 0;
}

int encapsulate_KEM(public_key_KEM *public_key_KEM, ciphertext *ciphertext,
                    shared_secret *shared_secret) {

    ciphertext->ciphertext_content = NULL;
    shared_secret->shared_secret_content = NULL;

    ciphertext->ciphertext_content = malloc(KEM_scheme->length_ciphertext);
    shared_secret->shared_secret_content =
        malloc(KEM_scheme->length_shared_secret);

    if ((ciphertext->ciphertext_content == NULL) ||
        (shared_secret->shared_secret_content == NULL)) {
        fprintf(stderr, "ERROR: malloc failed!\n");
        return 1;
    }

    OQS_STATUS rc = OQS_KEM_encaps(KEM_scheme, ciphertext->ciphertext_content,
                                   shared_secret->shared_secret_content,
                                   public_key_KEM->public_key_content);

    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_KEM_encaps failed!\n");
        return 2;
    }

    ciphertext->ciphertext_length = KEM_scheme->length_ciphertext;
    shared_secret->shared_secret_length = KEM_scheme->length_shared_secret;

    return 0;
}

int decapsulate_KEM(secret_key_KEM *secret_key_KEM, ciphertext *ciphertext_KEM,
                    shared_secret *shared_secret) {

    shared_secret->shared_secret_content = NULL;

    shared_secret->shared_secret_content =
        malloc(KEM_scheme->length_shared_secret);

    if (shared_secret->shared_secret_content == NULL) {
        fprintf(stderr, "ERROR: malloc failed!\n");
        return 1;
    }

    OQS_STATUS rc = OQS_KEM_decaps(
        KEM_scheme, shared_secret->shared_secret_content,
        ciphertext_KEM->ciphertext_content, secret_key_KEM->secret_key_content);

    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: OQS_KEM_decaps failed!\n");
        return 2;
    }

    shared_secret->shared_secret_length = KEM_scheme->length_shared_secret;

    return 0;
}

int terminate_KEM() {

    OQS_KEM_free(KEM_scheme);

    return 0;
}

void free_key_pair_KEM(secret_key_KEM *secret_key_KEM,
                       public_key_KEM *public_key_KEM) {

    OQS_MEM_secure_free(secret_key_KEM->secret_key_content,
                        secret_key_KEM->secret_key_length);
    OQS_MEM_insecure_free(public_key_KEM->public_key_content);

    return;
}

void free_ciphertext_KEM(ciphertext *ciphertext) {

    free(ciphertext->ciphertext_content);

    return;
}

void free_shared_secret_KEM(shared_secret *shared_secret) {

    free(shared_secret->shared_secret_content);

    return;
}

#include <oqs/oqs.h>

#include "../include/header_SIG.h"

//#define NUMBER_NIST_FINALIST_SIG 44

#define NUMBER_NIST_FINALIST_SIG 2

OQS_SIG *SIG_scheme;

char *name_nist_finalist_full_list_sig[44] = {"Dilithium2", "Dilithium3", "Dilithium5", "Dilithium2-AES", "Dilithium3-AES", "Dilithium5-AES", "Falcon-512", "Falcon-1024", "SPHINCS+-Haraka-128f-robust", "SPHINCS+-Haraka-128f-simple", "SPHINCS+-Haraka-128s-robust", "SPHINCS+-Haraka-128s-simple", "SPHINCS+-Haraka-192f-robust", "SPHINCS+-Haraka-192f-simple", "SPHINCS+-Haraka-192s-robust", "SPHINCS+-Haraka-192s-simple", "SPHINCS+-Haraka-256f-robust", "SPHINCS+-Haraka-256f-simple", "SPHINCS+-Haraka-256s-robust", "SPHINCS+-Haraka-256s-simple", "SPHINCS+-SHA256-128f-robust", "SPHINCS+-SHA256-128f-simple", "SPHINCS+-SHA256-128s-robust", "SPHINCS+-SHA256-128s-simple", "SPHINCS+-SHA256-192f-robust", "SPHINCS+-SHA256-192f-simple", "SPHINCS+-SHA256-192s-robust", "SPHINCS+-SHA256-192s-simple", "SPHINCS+-SHA256-256f-robust", "SPHINCS+-SHA256-256f-simple", "SPHINCS+-SHA256-256s-robust", "SPHINCS+-SHA256-256s-simple", "SPHINCS+-SHAKE256-128f-robust", "SPHINCS+-SHAKE256-128f-simple", "SPHINCS+-SHAKE256-128s-robust", "SPHINCS+-SHAKE256-128s-simple", "SPHINCS+-SHAKE256-192f-robust", "SPHINCS+-SHAKE256-192f-simple", "SPHINCS+-SHAKE256-192s-robust", "SPHINCS+-SHAKE256-192s-simple", "SPHINCS+-SHAKE256-256f-robust", "SPHINCS+-SHAKE256-256f-simple", "SPHINCS+-SHAKE256-256s-robust", "SPHINCS+-SHAKE256-256s-simple"};

char *name_nist_finalist_sig[NUMBER_NIST_FINALIST_SIG] = {"Dilithium2", "Falcon-512"};

int get_number_of_SIG() { return NUMBER_NIST_FINALIST_SIG; }

const char *get_name_SIG(int index) { return name_nist_finalist_sig[index]; }

int get_NIST_security_level_SIG(const char *SIG_scheme_name) {

    OQS_SIG *instance_tmp = OQS_SIG_new(SIG_scheme_name);

    int result = instance_tmp->claimed_nist_level;

    OQS_SIG_free(instance_tmp);

    return result;
}

int instantiate_SIG(const char *SIG_scheme_name) {

    int i = 0;

    SIG_scheme = NULL;

    SIG_scheme = OQS_SIG_new(SIG_scheme_name);

    if (SIG_scheme == NULL) {
        fprintf(stderr, "ERROR: ");
        while (SIG_scheme_name[i] != '\0') {
            fprintf(stderr, "%c", SIG_scheme_name[i]);
            ++i;
        }
        fprintf(stderr, " was not enabled at compile-time.\n");
        return 1;
    }

    return 0;
}

int key_gen_SIG(secret_key_SIG *secret_key_SIG,
                public_key_SIG *public_key_SIG) {

    public_key_SIG->public_key_content = NULL;
    secret_key_SIG->secret_key_content = NULL;

    public_key_SIG->public_key_content = malloc(SIG_scheme->length_public_key);
    secret_key_SIG->secret_key_content = malloc(SIG_scheme->length_secret_key);

    if ((public_key_SIG->public_key_content == NULL) ||
        (secret_key_SIG->secret_key_content == NULL)) {
        fprintf(stderr, "ERROR: malloc failed!\n");
        return 1;
    }

    OQS_STATUS rc =
        OQS_SIG_keypair(SIG_scheme, public_key_SIG->public_key_content,
                        secret_key_SIG->secret_key_content);

    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: key_gen_SIG failed!\n");
        return 2;
    }

    public_key_SIG->public_key_length = SIG_scheme->length_public_key;
    secret_key_SIG->secret_key_length = SIG_scheme->length_secret_key;

    return 0;
}

int sign_SIG(secret_key_SIG *secret_key_SIG, message *message,
             signature *signature) {

    signature->signature_content = NULL;

    signature->signature_content = malloc(SIG_scheme->length_signature);

    if (signature->signature_content == NULL) {
        fprintf(stderr, "ERROR: malloc failed!\n");
        return 1;
    }

    OQS_STATUS rc = OQS_SIG_sign(
        SIG_scheme, signature->signature_content, &signature->signature_length,
        message->message_content, message->message_length,
        secret_key_SIG->secret_key_content);

    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: verify_SIG failed!\n");
        return 2;
    }

    return 0;
}

int verify_SIG(public_key_SIG *public_key_SIG, message *message,
               signature *signature) {

    OQS_STATUS rc = OQS_SIG_verify(
        SIG_scheme, message->message_content, message->message_length,
        signature->signature_content, signature->signature_length,
        public_key_SIG->public_key_content);

    if (rc != OQS_SUCCESS) {
        fprintf(stderr, "ERROR: verify_SIG failed!\n");
        return 1;
    }

    return 0;
}

int terminate_SIG() {

    OQS_SIG_free(SIG_scheme);

    return 0;
}

void free_key_pair_SIG(secret_key_SIG *secret_key_SIG,
                       public_key_SIG *public_key_SIG) {

    OQS_MEM_secure_free(secret_key_SIG->secret_key_content,
                        secret_key_SIG->secret_key_length);
    OQS_MEM_insecure_free(public_key_SIG->public_key_content);

    return;
}

void free_message(message *message) {

    free(message->message_content);

    return;
}

void free_signature(signature *signature) {

    OQS_MEM_insecure_free(signature->signature_content);

    return;
}

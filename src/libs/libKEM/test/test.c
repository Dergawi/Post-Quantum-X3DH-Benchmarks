#include "../include/header_KEM.h"

int main() {

    public_key_KEM public_key_KEM;
    secret_key_KEM secret_key_KEM;
    ciphertext ciphertext;
    shared_secret shared_secret_1;
    shared_secret shared_secret_2;
    int error = 0;

    instantiate_KEM("BIKE-L1");

    key_gen_KEM(&secret_key_KEM, &public_key_KEM);

    encapsulate_KEM(&public_key_KEM, &ciphertext, &shared_secret_1);

    decapsulate_KEM(&secret_key_KEM, &ciphertext, &shared_secret_2);

    for (int i = 0; i < shared_secret_1.shared_secret_length; i++) {
        if (((char *)shared_secret_1.shared_secret_content)[i] !=
            ((char *)shared_secret_2.shared_secret_content)[i]) {
            error++;
        }
    }

    if (error) {
        fprintf(stderr, "Test failed, shared secrets are different\n");
    } else {
        fprintf(stderr, "Test successful\n");
    }

    terminate_KEM();

    free_key_pair_KEM(&secret_key_KEM, &public_key_KEM);
    free_ciphertext_KEM(&ciphertext);
    free_shared_secret_KEM(&shared_secret_1);
    free_shared_secret_KEM(&shared_secret_2);

    return 0;
}
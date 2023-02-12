#include <stdio.h>
#include <stdlib.h>

#include "../include/header_SplitKEM.h"

int main() {

    public_key_SKEM public_key_SKEM_1;
    public_key_SKEM public_key_SKEM_2;
    secret_key_SKEM secret_key_SKEM_1;
    secret_key_SKEM secret_key_SKEM_2;
    ciphertext ciphertext;
    shared_secret shared_secret_1;
    shared_secret shared_secret_2;

    initiate_SKEM();

    key_gen_SKEM(&secret_key_SKEM_1, &public_key_SKEM_1);
    key_gen_SKEM(&secret_key_SKEM_2, &public_key_SKEM_2);

    encapsulate_SKEM(&secret_key_SKEM_2, &public_key_SKEM_2, &public_key_SKEM_1,
                     &ciphertext, &shared_secret_1);

    decapsulate_SKEM(&secret_key_SKEM_1, &public_key_SKEM_1, &public_key_SKEM_2,
                     &ciphertext, &shared_secret_2);

    int i = 0;
    for (; i < shared_secret_1.shared_secret_length; i++)
        printf("0x%.2x ",
               ((unsigned char *)shared_secret_1.shared_secret_content)[i]);
    printf("\n");

    i = 0;
    for (; i < shared_secret_2.shared_secret_length; i++)
        printf("0x%.2x ",
               ((unsigned char *)shared_secret_2.shared_secret_content)[i]);
    printf("\n");

    terminate_SKEM();

    free_key_pair_SKEM(&secret_key_SKEM_1, &public_key_SKEM_1);
    free_key_pair_SKEM(&secret_key_SKEM_2, &public_key_SKEM_2);
    free_ciphertext_SKEM(&ciphertext);
    free_shared_secret_SKEM(&shared_secret_1);
    free_shared_secret_SKEM(&shared_secret_2);

    return 0;
}

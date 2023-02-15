#include "../include/header_SIG.h"

int main() {

    public_key_SIG public_key_SIG;
    secret_key_SIG secret_key_SIG;
    message_SIG message;
    signature_SIG signature;

    unsigned char m[] = "Raptor: next generation of Falcon with stealth mode";

    message.message_content = m;
    message.message_length = 16;

    instantiate_SIG("Dilithium2");

    key_gen_SIG(&secret_key_SIG, &public_key_SIG);

    sign_SIG(&secret_key_SIG, &message, &signature);

    verify_SIG(&public_key_SIG, &message, &signature);

    terminate_SIG();

    fprintf(stderr, "Test successful\n");

    free_key_pair_SIG(&secret_key_SIG, &public_key_SIG);
    free_signature_SIG(&signature);

    return 0;
}

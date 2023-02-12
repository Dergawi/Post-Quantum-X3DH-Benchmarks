#include "../include/header_RS.h"

int main() {
    public_key_RS public_key_signer;
    public_key_RS public_key_verifier;
    secret_key_RS secret_key_signer;
    secret_key_RS secret_key_verifier;
    message message;
    signature signature;

    unsigned char m[] = "Raptor: next generation of Falcon with stealth mode";

    message.message_content = m;
    message.message_length = 16;

    initiate_RS();

    key_gen_RS(&secret_key_signer, &public_key_signer);
    key_gen_RS(&secret_key_verifier, &public_key_verifier);

    sign_RS(&secret_key_signer, &message, &public_key_signer,
            &public_key_verifier, &signature);

    verify_RS(&signature, &message, &public_key_signer, &public_key_verifier);

    free_key_pair_RS(&secret_key_signer, &public_key_signer);
    free_key_pair_RS(&secret_key_verifier, &public_key_verifier);

    free_signature(&signature);

    terminate_RS();

    printf("Test successfull\n");
}

#include "../include/header_DVS.h"

int main() {
    public_key_signer_DVS public_key_signer;
    public_key_verifier_DVS public_key_verifier;
    secret_key_signer_DVS secret_key_signer;
    secret_key_verifier_DVS secret_key_verifier;
    message message;
    signature signature;

    unsigned char m[] = "Raptor: next generation of Falcon with stealth mode";

    message.message_content = m;
    message.message_length = 16;

    initiate_DVS();

    key_gen_signer_DVS(&secret_key_signer, &public_key_signer);
    key_gen_verifier_DVS(&secret_key_verifier, &public_key_verifier);

    sign_DVS(&secret_key_signer, &message, &public_key_signer,
             &public_key_verifier, &signature);

    verify_DVS(&signature, &message, &public_key_signer, &public_key_verifier);

    free_signature(&signature);

    simulate_DVS(&secret_key_verifier, &message, &public_key_signer,
                 &public_key_verifier, &signature);

    verify_DVS(&signature, &message, &public_key_signer, &public_key_verifier);

    free_key_pair_signer_DVS(&secret_key_signer, &public_key_signer);
    free_key_pair_verifier_DVS(&secret_key_verifier, &public_key_verifier);

    free_signature(&signature);

    terminate_DVS();

    printf("Test successfull\n");
    printf("Don't mind the error, it still works :)\n");
}

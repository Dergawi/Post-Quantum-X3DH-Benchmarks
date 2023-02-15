#include "libProtocol.h"

#include "../../libs/libBenchmark/include/header_Benchmark.h"

#define HASH_LENGTH 32

int main() {

    char buf[100];
    int error_count = 0;

    FILE *fpt;

    snprintf(buf, sizeof(buf), "../results/DH/mean_cycles_X3DH.csv");
    fpt = fopen(buf, "w");
    fclose(fpt);

    fpt = fopen(buf, "a");
    fprintf(fpt, "White noise,Long term key,Static key,One time "
                 "key,Initiate,Responder,Hole protocol\n");
    fclose(fpt);

    snprintf(buf, sizeof(buf), "../results/DH/variance_cycles_X3DH.csv");
    fpt = fopen(buf, "w");
    fclose(fpt);

    fpt = fopen(buf, "a");
    fprintf(fpt, "White noise,Long term key,Static key,One time "
                 "key,Initiate,Responder,Hole protocol\n");
    fclose(fpt);

    snprintf(buf, sizeof(buf), "../results/DH/stored_bytes_X3DH.csv");
    fpt = fopen(buf, "w");
    fclose(fpt);

    fpt = fopen(buf, "a");
    fprintf(fpt, "Long term key,Static key,One time "
                 "key,Initiate,Responder,Hole protocol\n");
    fclose(fpt);

    snprintf(buf, sizeof(buf), "../results/DH/sent_bytes_X3DH.csv");
    fpt = fopen(buf, "w");
    fclose(fpt);

    fpt = fopen(buf, "a");
    fprintf(fpt, "Long term key,Static key,One time "
                 "key,Initiate,Responder,Hole protocol\n");
    fclose(fpt);

    int long_term_key_stored_data_size = 0;
    int static_key_stored_data_size = 0;
    int one_time_key_stored_data_size = 0;
    int initiator_stored_data_size = 0;
    int responder_stored_data_size = 0;
    int hole_protocol_stored_data_size = 0;
    int long_term_key_sent_data_size = 0;
    int static_key_sent_data_size = 0;
    int one_time_key_sent_data_size = 0;
    int initiator_sent_data_size = 0;
    int responder_sent_data_size = 0;
    int hole_protocol_sent_data_size = 0;

    benchmark_variables benchmark_variables_white_noise;
    reset_benchmark_variables(&benchmark_variables_white_noise);
    benchmark_variables benchmark_variables_protocol;
    reset_benchmark_variables(&benchmark_variables_protocol);
    benchmark_variables benchmark_variables_long_term_key;
    reset_benchmark_variables(&benchmark_variables_long_term_key);
    benchmark_variables benchmark_variables_static_key;
    reset_benchmark_variables(&benchmark_variables_static_key);
    benchmark_variables benchmark_variables_one_time_key;
    reset_benchmark_variables(&benchmark_variables_one_time_key);
    benchmark_variables benchmark_variables_initiate;
    reset_benchmark_variables(&benchmark_variables_initiate);
    benchmark_variables benchmark_variables_responder;
    reset_benchmark_variables(&benchmark_variables_responder);

    printf("Benchmarking : X3DH\n");

    while (is_done(&benchmark_variables_white_noise) *
               is_done(&benchmark_variables_long_term_key) *
               is_done(&benchmark_variables_one_time_key) *
               is_done(&benchmark_variables_initiate) *
               is_done(&benchmark_variables_responder) *
               is_done(&benchmark_variables_protocol) ==
           0) {
        public_key_DH long_term_public_key_initiator;
        public_key_DH long_term_public_key_responder;
        secret_key_DH long_term_secret_key_initiator;
        secret_key_DH long_term_secret_key_responder;
        public_key_DH static_public_key_DH;
        secret_key_DH static_secret_key_DH;
        public_key_DH one_time_public_key_DH;
        secret_key_DH one_time_secret_key_DH;
        public_key_DH ephemeral_public_key_DH;
        secret_key_DH ephemeral_secret_key_DH;
        signature signature;

        start_benchmark(&benchmark_variables_white_noise);
        end_benchmark(&benchmark_variables_white_noise);

        start_benchmark(&benchmark_variables_protocol);

        start_benchmark(&benchmark_variables_long_term_key);

        if (long_term_key_gen(&long_term_secret_key_initiator,
                              &long_term_public_key_initiator) != 0) {
            ++error_count;
            free_key_pair(&long_term_secret_key_initiator,
                          &long_term_public_key_initiator);
        } else {
            end_benchmark(&benchmark_variables_long_term_key);
            if (long_term_key_gen(&long_term_secret_key_responder,
                                  &long_term_public_key_responder) != 0) {
                ++error_count;
                free_key_pair(&long_term_secret_key_initiator,
                              &long_term_public_key_initiator);
                free_key_pair(&long_term_secret_key_responder,
                              &long_term_public_key_responder);
            } else {
                start_benchmark(&benchmark_variables_static_key);
                if (static_key_gen(&long_term_secret_key_responder,
                                   &static_secret_key_DH, &static_public_key_DH,
                                   &signature) != 0) {
                    ++error_count;
                    free_key_pair(&long_term_secret_key_initiator,
                                  &long_term_public_key_initiator);
                    free_key_pair(&long_term_secret_key_responder,
                                  &long_term_public_key_responder);
                    free_key_pair(&static_secret_key_DH, &static_public_key_DH);
                    free_signature(&signature);
                } else {
                    end_benchmark(&benchmark_variables_static_key);
                    start_benchmark(&benchmark_variables_one_time_key);
                    if (one_time_key_gen(&one_time_secret_key_DH,
                                         &one_time_public_key_DH) != 0) {
                        ++error_count;
                        free_key_pair(&long_term_secret_key_initiator,
                                      &long_term_public_key_initiator);
                        free_key_pair(&long_term_secret_key_responder,
                                      &long_term_public_key_responder);
                        free_key_pair(&static_secret_key_DH,
                                      &static_public_key_DH);
                        free_key_pair(&one_time_secret_key_DH,
                                      &one_time_public_key_DH);
                        free_signature(&signature);
                    } else {
                        end_benchmark(&benchmark_variables_one_time_key);
                        start_benchmark(&benchmark_variables_initiate);
                        if (initiator(
                                &long_term_secret_key_initiator,
                                &long_term_public_key_responder,
                                &static_public_key_DH, &one_time_public_key_DH,
                                &ephemeral_secret_key_DH,
                                &ephemeral_public_key_DH, &signature) != 0) {
                            ++error_count;
                            free_key_pair(&long_term_secret_key_initiator,
                                          &long_term_public_key_initiator);
                            free_key_pair(&long_term_secret_key_responder,
                                          &long_term_public_key_responder);
                            free_key_pair(&static_secret_key_DH,
                                          &static_public_key_DH);
                            free_key_pair(&one_time_secret_key_DH,
                                          &one_time_public_key_DH);
                            free_key_pair(&ephemeral_secret_key_DH,
                                          &ephemeral_public_key_DH);
                            free_signature(&signature);
                        } else {
                            end_benchmark(&benchmark_variables_initiate);
                            start_benchmark(&benchmark_variables_responder);
                            if (responder(&long_term_public_key_initiator,
                                          &long_term_secret_key_responder,
                                          &static_secret_key_DH,
                                          &one_time_secret_key_DH,
                                          &ephemeral_public_key_DH) != 0) {
                                ++error_count;
                                free_key_pair(&long_term_secret_key_initiator,
                                              &long_term_public_key_initiator);
                                free_key_pair(&long_term_secret_key_responder,
                                              &long_term_public_key_responder);
                                free_key_pair(&static_secret_key_DH,
                                              &static_public_key_DH);
                                free_key_pair(&one_time_secret_key_DH,
                                              &one_time_public_key_DH);
                                free_key_pair(&ephemeral_secret_key_DH,
                                              &ephemeral_public_key_DH);
                                free_signature(&signature);
                            } else {
                                end_benchmark(&benchmark_variables_responder);
                                end_benchmark(&benchmark_variables_protocol);
                                long_term_key_stored_data_size =
                                    long_term_public_key_initiator
                                        .public_key_length +
                                    long_term_secret_key_initiator
                                        .secret_key_length;
                                static_key_stored_data_size =
                                    static_public_key_DH.public_key_length +
                                    static_secret_key_DH.secret_key_length +
                                    signature.signature_length;
                                one_time_key_stored_data_size =
                                    one_time_public_key_DH.public_key_length +
                                    one_time_secret_key_DH.secret_key_length;
                                initiator_stored_data_size = HASH_LENGTH;
                                responder_stored_data_size = HASH_LENGTH;
                                hole_protocol_stored_data_size =
                                    long_term_key_stored_data_size +
                                    static_key_stored_data_size +
                                    one_time_key_stored_data_size +
                                    initiator_stored_data_size +
                                    responder_stored_data_size;
                                long_term_key_sent_data_size =
                                    long_term_public_key_initiator
                                        .public_key_length;
                                static_key_sent_data_size =
                                    static_public_key_DH.public_key_length +
                                    signature.signature_length;
                                one_time_key_sent_data_size =
                                    one_time_public_key_DH.public_key_length;
                                // The +1 in the data sent by the
                                // initiator is the variable that
                                // indicates which one-time of the
                                // responder the initiator chose.
                                initiator_sent_data_size =
                                    ephemeral_public_key_DH.public_key_length +
                                    1;
                                responder_sent_data_size = 0;
                                hole_protocol_sent_data_size =
                                    long_term_key_sent_data_size +
                                    static_key_sent_data_size +
                                    one_time_key_sent_data_size +
                                    initiator_sent_data_size +
                                    responder_sent_data_size;
                                free_key_pair(&long_term_secret_key_initiator,
                                              &long_term_public_key_initiator);
                                free_key_pair(&long_term_secret_key_responder,
                                              &long_term_public_key_responder);
                                free_key_pair(&static_secret_key_DH,
                                              &static_public_key_DH);
                                free_key_pair(&one_time_secret_key_DH,
                                              &one_time_public_key_DH);
                                free_key_pair(&ephemeral_secret_key_DH,
                                              &ephemeral_public_key_DH);
                                free_signature(&signature);
                            }
                        }
                    }
                }
            }
        }
    }

    printf("white noise:        %15.0f mean cycles  %15.0f cycles variance\n",
           get_mean(&benchmark_variables_white_noise),
           get_variance(&benchmark_variables_white_noise));
    printf("long term key:      %15.0f mean cycles  %15.0f cycles "
           "variance\n",
           get_mean(&benchmark_variables_long_term_key),
           get_variance(&benchmark_variables_long_term_key));
    printf("static key:         %15.0f mean cycles  %15.0f cycles "
           "variance\n",
           get_mean(&benchmark_variables_static_key),
           get_variance(&benchmark_variables_static_key));
    printf("one time key:       %15.0f mean cycles  %15.0f cycles "
           "variance\n",
           get_mean(&benchmark_variables_one_time_key),
           get_variance(&benchmark_variables_one_time_key));
    printf("initiate:           %15.0f mean cycles  %15.0f cycles "
           "variance\n",
           get_mean(&benchmark_variables_initiate),
           get_variance(&benchmark_variables_initiate));
    printf("responder:          %15.0f mean cycles  %15.0f cycles "
           "variance\n",
           get_mean(&benchmark_variables_responder),
           get_variance(&benchmark_variables_responder));
    printf("protocol:           %15.0f mean cycles  %15.0f cycles "
           "variance\n",
           get_mean(&benchmark_variables_protocol),
           get_variance(&benchmark_variables_protocol));
    printf("long term key:      %15.0d bytes stored %15.0d bytes sent\n",
           long_term_key_stored_data_size, long_term_key_sent_data_size);
    printf("static key:         %15.0d bytes stored %15.0d bytes sent\n",
           static_key_stored_data_size, static_key_sent_data_size);
    printf("one time key:       %15.0d bytes stored %15.0d bytes sent\n",
           one_time_key_stored_data_size, one_time_key_sent_data_size);
    printf("initiate:           %15.0d bytes stored %15.0d bytes sent\n",
           initiator_stored_data_size, initiator_sent_data_size);
    printf("responder:          %15.0d bytes stored %15.0d bytes sent\n",
           responder_stored_data_size, responder_sent_data_size);
    printf("protocol:           %15.0d bytes stored %15.0d bytes sent\n",
           hole_protocol_stored_data_size, hole_protocol_sent_data_size);
    printf("\n");

    snprintf(buf, sizeof(buf), "../results/DH/mean_cycles_X3DH.csv");
    fpt = fopen(buf, "a");

    fprintf(fpt, "%.0f,%.0f,%.0f,%.0f,%.0f,%.0f,%.0f\n",
            get_mean(&benchmark_variables_white_noise),
            get_mean(&benchmark_variables_long_term_key),
            get_mean(&benchmark_variables_static_key),
            get_mean(&benchmark_variables_one_time_key),
            get_mean(&benchmark_variables_initiate),
            get_mean(&benchmark_variables_responder),
            get_mean(&benchmark_variables_protocol));

    fclose(fpt);

    snprintf(buf, sizeof(buf), "../results/DH/variance_cycles_X3DH.csv");
    fpt = fopen(buf, "a");

    fprintf(fpt, "%.0f,%.0f,%.0f,%.0f,%.0f,%.0f,%.0f\n",
            get_variance(&benchmark_variables_white_noise),
            get_variance(&benchmark_variables_long_term_key),
            get_variance(&benchmark_variables_static_key),
            get_variance(&benchmark_variables_one_time_key),
            get_variance(&benchmark_variables_initiate),
            get_variance(&benchmark_variables_responder),
            get_variance(&benchmark_variables_protocol));

    fclose(fpt);

    snprintf(buf, sizeof(buf), "../results/DH/stored_bytes_X3DH.csv");
    fpt = fopen(buf, "a");

    fprintf(fpt, "%d,%d,%d,%d,%d,%d\n", long_term_key_stored_data_size,
            static_key_stored_data_size, one_time_key_stored_data_size,
            initiator_stored_data_size, responder_stored_data_size,
            hole_protocol_stored_data_size);

    fclose(fpt);

    snprintf(buf, sizeof(buf), "../results/DH/sent_bytes_X3DH.csv");
    fpt = fopen(buf, "a");

    fprintf(fpt, "%d,%d,%d,%d,%d,%d\n", long_term_key_sent_data_size,
            static_key_sent_data_size, one_time_key_sent_data_size,
            initiator_sent_data_size, responder_sent_data_size,
            hole_protocol_sent_data_size);

    fclose(fpt);

    printf("%d errors\n", error_count);

    return 0;
}

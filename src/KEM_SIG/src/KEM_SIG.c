#include "libProtocol.h"

#include "../../libs/libBenchmark/include/header_Benchmark.h"

int main(int argc, char const *argv[]) {

    if (argc != 2) {
        fprintf(stderr,
                "You need to provide the required NIST security level\n");
        fprintf(stderr, "Usage : KEM_SIG(_sanitized) <NIST security level>\n");
        return 1;
    }

    char buf[100];
    int error_count = 0;
    int list_corresponding_NIST_level_bit_security[5] = {192, 256, 288, 384,
                                                         384};
    int is_secure_KEM = 1;
    int is_secure_SIG = 1;

    unsigned int requested_NIST_security_level = strtol(argv[1], NULL, 10);

    FILE *fpt;

    snprintf(buf, sizeof(buf),
             "../results/KEM_SIG/mean_cycles_KEM_SIG_NIST_level_%d.csv",
             requested_NIST_security_level);
    fpt = fopen(buf, "w");
    fclose(fpt);

    fpt = fopen(buf, "a");
    fprintf(fpt,
            "KEM,White Noise,Protocol Setup,Long term key,Static key,One time "
            "key,Initiate,Responder,Hole protocol\n");
    fclose(fpt);

    snprintf(buf, sizeof(buf),
             "../results/KEM_SIG/variance_cycles_KEM_SIG_NIST_level_%d.csv",
             requested_NIST_security_level);
    fpt = fopen(buf, "w");
    fclose(fpt);

    fpt = fopen(buf, "a");
    fprintf(fpt,
            "KEM,White Noise,Protocol Setup,Long term key,Static key,One time "
            "key,Initiate,Responder,Hole protocol\n");
    fclose(fpt);

    snprintf(buf, sizeof(buf),
             "../results/KEM_SIG/stored_bytes_KEM_SIG_NIST_level_%d.csv",
             requested_NIST_security_level);
    fpt = fopen(buf, "w");
    fclose(fpt);

    fpt = fopen(buf, "a");
    fprintf(fpt, "KEM,Long term key,Static key,One time "
                 "key,Initiate,Responder,Hole protocol\n");
    fclose(fpt);

    snprintf(buf, sizeof(buf),
             "../results/KEM_SIG/sent_bytes_KEM_SIG_NIST_level_%d.csv",
             requested_NIST_security_level);
    fpt = fopen(buf, "w");
    fclose(fpt);

    fpt = fopen(buf, "a");
    fprintf(fpt, "KEM,Long term key,Static key,One time "
                 "key,Initiate,Responder,Hole protocol\n");
    fclose(fpt);

    benchmark_variables benchmark_variables_white_noise;
    reset_benchmark_variables(&benchmark_variables_white_noise);
    benchmark_variables benchmark_variables_initiate_protocol;
    reset_benchmark_variables(&benchmark_variables_initiate_protocol);

    for (int i = 0; i < get_number_of_KEM(); i++) {

        is_secure_KEM = 1;
        if (get_NIST_security_level_KEM(get_name_KEM(i)) <
            requested_NIST_security_level) {
            is_secure_KEM = 0;
        }

        for (int j = 0; j < get_number_of_SIG(); j++) {

            is_secure_SIG = 1;
            if (get_NIST_security_level_SIG(get_name_SIG(j)) <
                requested_NIST_security_level) {
                is_secure_SIG = 0;
            }

            if (is_secure_KEM && is_secure_SIG) {

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

                printf("Benchmarking : \"");
                int k = 0;
                while (get_name_SIG(j)[k] != '\0') {
                    printf("%c", get_name_SIG(j)[k]);
                    ++k;
                }
                printf("\" (NIST security level of %d) with \"",
                       get_NIST_security_level_SIG(get_name_SIG(j)));
                k = 0;
                while (get_name_KEM(i)[k] != '\0') {
                    printf("%c", get_name_KEM(i)[k]);
                    ++k;
                }
                printf("\" (NIST security level of %d)\n",
                       get_NIST_security_level_KEM(get_name_KEM(i)));

                while (is_done(&benchmark_variables_white_noise) *
                           is_done(&benchmark_variables_initiate_protocol) *
                           is_done(&benchmark_variables_long_term_key) *
                           is_done(&benchmark_variables_static_key) *
                           is_done(&benchmark_variables_one_time_key) *
                           is_done(&benchmark_variables_initiate) *
                           is_done(&benchmark_variables_responder) *
                           is_done(&benchmark_variables_protocol) ==
                       0) {
                    long_term_public_key long_term_public_key_initiator;
                    long_term_public_key long_term_public_key_responder;
                    static_public_key static_public_key_responder;
                    one_time_public_key one_time_public_key_responder;
                    long_term_secret_key long_term_secret_key_initiator;
                    long_term_secret_key long_term_secret_key_responder;
                    static_secret_key static_secret_key_responder;
                    one_time_secret_key one_time_secret_key_responder;
                    ciphertext ciphertext_1;
                    ciphertext ciphertext_2;
                    ciphertext ciphertext_3;

                    start_benchmark(&benchmark_variables_white_noise);
                    end_benchmark(&benchmark_variables_white_noise);

                    start_benchmark(&benchmark_variables_protocol);

                    start_benchmark(&benchmark_variables_initiate_protocol);

                    initiate_protocol(get_name_KEM(i), get_name_SIG(j));

                    end_benchmark(&benchmark_variables_initiate_protocol);
                    start_benchmark(&benchmark_variables_long_term_key);
                    if (long_term_key_gen(&long_term_secret_key_initiator,
                                          &long_term_public_key_initiator) !=
                        0) {
                        ++error_count;
                        free_long_term_key_pair(
                            &long_term_secret_key_initiator,
                            &long_term_public_key_initiator);
                    } else {
                        end_benchmark(&benchmark_variables_long_term_key);
                        if (long_term_key_gen(
                                &long_term_secret_key_responder,
                                &long_term_public_key_responder) != 0) {
                            ++error_count;
                            free_long_term_key_pair(
                                &long_term_secret_key_initiator,
                                &long_term_public_key_initiator);
                            free_long_term_key_pair(
                                &long_term_secret_key_responder,
                                &long_term_public_key_responder);
                        } else {
                            start_benchmark(&benchmark_variables_static_key);
                            if (static_key_gen(&static_secret_key_responder,
                                               &long_term_secret_key_responder,
                                               &static_public_key_responder) !=
                                0) {
                                ++error_count;
                                free_long_term_key_pair(
                                    &long_term_secret_key_initiator,
                                    &long_term_public_key_initiator);
                                free_long_term_key_pair(
                                    &long_term_secret_key_responder,
                                    &long_term_public_key_responder);
                                free_static_key_pair(
                                    &static_secret_key_responder,
                                    &static_public_key_responder);
                            } else {
                                end_benchmark(&benchmark_variables_static_key);
                                start_benchmark(
                                    &benchmark_variables_one_time_key);
                                if (one_time_key_gen(
                                        &one_time_secret_key_responder,
                                        &one_time_public_key_responder) != 0) {
                                    ++error_count;
                                    free_long_term_key_pair(
                                        &long_term_secret_key_initiator,
                                        &long_term_public_key_initiator);
                                    free_long_term_key_pair(
                                        &long_term_secret_key_responder,
                                        &long_term_public_key_responder);
                                    free_static_key_pair(
                                        &static_secret_key_responder,
                                        &static_public_key_responder);
                                    free_one_time_key_pair(
                                        &one_time_secret_key_responder,
                                        &one_time_public_key_responder);
                                } else {
                                    end_benchmark(
                                        &benchmark_variables_one_time_key);
                                    start_benchmark(
                                        &benchmark_variables_initiate);
                                    if (initiator(
                                            &long_term_public_key_responder,
                                            &static_public_key_responder,
                                            &one_time_public_key_responder,
                                            &ciphertext_1, &ciphertext_2,
                                            &ciphertext_3,
                                            list_corresponding_NIST_level_bit_security
                                                    [requested_NIST_security_level] /
                                                8) != 0) {
                                        ++error_count;
                                        free_long_term_key_pair(
                                            &long_term_secret_key_initiator,
                                            &long_term_public_key_initiator);
                                        free_long_term_key_pair(
                                            &long_term_secret_key_responder,
                                            &long_term_public_key_responder);
                                        free_static_key_pair(
                                            &static_secret_key_responder,
                                            &static_public_key_responder);
                                        free_one_time_key_pair(
                                            &one_time_secret_key_responder,
                                            &one_time_public_key_responder);
                                        free_ciphertext_KEM(&ciphertext_1);
                                        free_ciphertext_KEM(&ciphertext_2);
                                        free_ciphertext_KEM(&ciphertext_3);
                                    } else {
                                        end_benchmark(
                                            &benchmark_variables_initiate);
                                        start_benchmark(
                                            &benchmark_variables_responder);
                                        if (responder(
                                                &long_term_secret_key_responder,
                                                &static_secret_key_responder,
                                                &one_time_secret_key_responder,
                                                &ciphertext_1, &ciphertext_2,
                                                &ciphertext_3,
                                                list_corresponding_NIST_level_bit_security
                                                        [requested_NIST_security_level] /
                                                    8) != 0) {
                                            ++error_count;
                                            free_long_term_key_pair(
                                                &long_term_secret_key_initiator,
                                                &long_term_public_key_initiator);
                                            free_long_term_key_pair(
                                                &long_term_secret_key_responder,
                                                &long_term_public_key_responder);
                                            free_static_key_pair(
                                                &static_secret_key_responder,
                                                &static_public_key_responder);
                                            free_one_time_key_pair(
                                                &one_time_secret_key_responder,
                                                &one_time_public_key_responder);
                                            free_ciphertext_KEM(&ciphertext_1);
                                            free_ciphertext_KEM(&ciphertext_2);
                                            free_ciphertext_KEM(&ciphertext_3);
                                        } else {
                                            end_benchmark(
                                                &benchmark_variables_responder);
                                            end_benchmark(
                                                &benchmark_variables_protocol);
                                            long_term_key_stored_data_size =
                                                long_term_public_key_initiator
                                                    .public_key_length +
                                                long_term_secret_key_initiator
                                                    .secret_key_length;
                                            static_key_stored_data_size =
                                                static_public_key_responder
                                                    .public_key_length +
                                                static_secret_key_responder
                                                    .secret_key_length;
                                            one_time_key_stored_data_size =
                                                one_time_public_key_responder
                                                    .public_key_length +
                                                one_time_secret_key_responder
                                                    .secret_key_length;
                                            initiator_stored_data_size =
                                                list_corresponding_NIST_level_bit_security
                                                    [requested_NIST_security_level] /
                                                8;
                                            responder_stored_data_size =
                                                list_corresponding_NIST_level_bit_security
                                                    [requested_NIST_security_level] /
                                                8;
                                            hole_protocol_stored_data_size =
                                                long_term_key_stored_data_size +
                                                one_time_key_stored_data_size +
                                                initiator_stored_data_size +
                                                responder_stored_data_size;
                                            long_term_key_sent_data_size =
                                                long_term_public_key_initiator
                                                    .public_key_length;
                                            static_key_sent_data_size =
                                                static_public_key_responder
                                                    .public_key_length;
                                            one_time_key_sent_data_size =
                                                one_time_public_key_responder
                                                    .public_key_length;
                                            initiator_sent_data_size =
                                                ciphertext_1.ciphertext_length +
                                                ciphertext_2.ciphertext_length +
                                                ciphertext_3.ciphertext_length;
                                            responder_sent_data_size = 0;
                                            hole_protocol_sent_data_size =
                                                long_term_key_sent_data_size +
                                                one_time_key_sent_data_size +
                                                initiator_sent_data_size +
                                                responder_sent_data_size;
                                            free_long_term_key_pair(
                                                &long_term_secret_key_initiator,
                                                &long_term_public_key_initiator);
                                            free_long_term_key_pair(
                                                &long_term_secret_key_responder,
                                                &long_term_public_key_responder);
                                            free_static_key_pair(
                                                &static_secret_key_responder,
                                                &static_public_key_responder);
                                            free_one_time_key_pair(
                                                &one_time_secret_key_responder,
                                                &one_time_public_key_responder);
                                            free_ciphertext_KEM(&ciphertext_1);
                                            free_ciphertext_KEM(&ciphertext_2);
                                            free_ciphertext_KEM(&ciphertext_3);
                                            terminate_protocol();
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                printf("white noise:        %15.0f mean cycles  %15.0f cycles "
                       "variance\n",
                       get_mean(&benchmark_variables_white_noise),
                       get_variance(&benchmark_variables_white_noise));
                printf("initiate_protocol:  %15.0f mean cycles  %15.0f cycles "
                       "variance\n",
                       get_mean(&benchmark_variables_initiate_protocol),
                       get_variance(&benchmark_variables_initiate_protocol));
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
                printf("long term key:      %15.0d bytes stored %15.0d bytes "
                       "sent\n",
                       long_term_key_stored_data_size,
                       long_term_key_sent_data_size);
                printf("static key:         %15.0d bytes stored %15.0d bytes "
                       "sent\n",
                       static_key_stored_data_size, static_key_sent_data_size);
                printf("one time key:       %15.0d bytes stored %15.0d bytes "
                       "sent\n",
                       one_time_key_stored_data_size,
                       one_time_key_sent_data_size);
                printf("initiate:           %15.0d bytes stored %15.0d bytes "
                       "sent\n",
                       initiator_stored_data_size, initiator_sent_data_size);
                printf("responder:          %15.0d bytes stored %15.0d bytes "
                       "sent\n",
                       responder_stored_data_size, responder_sent_data_size);
                printf("protocol:           %15.0d bytes stored %15.0d bytes "
                       "sent\n",
                       hole_protocol_stored_data_size,
                       hole_protocol_sent_data_size);
                printf("\n");

                snprintf(
                    buf, sizeof(buf),
                    "../results/KEM_SIG/mean_cycles_KEM_SIG_NIST_level_%d.csv",
                    requested_NIST_security_level);
                fpt = fopen(buf, "a");

                k = 0;
                while (get_name_KEM(i)[k] != '\0') {
                    fprintf(fpt, "%c", get_name_KEM(i)[k]);
                    ++k;
                }
                fprintf(fpt, " + ");
                k = 0;
                while (get_name_SIG(j)[k] != '\0') {
                    fprintf(fpt, "%c", get_name_SIG(j)[k]);
                    ++k;
                }
                fprintf(fpt, ",");

                fprintf(fpt, "%.0f,%.0f,%.0f,%.0f,%.0f,%.0f,%.0f,%.0f\n",
                        get_mean(&benchmark_variables_white_noise),
                        get_mean(&benchmark_variables_initiate_protocol),
                        get_mean(&benchmark_variables_long_term_key),
                        get_mean(&benchmark_variables_static_key),
                        get_mean(&benchmark_variables_one_time_key),
                        get_mean(&benchmark_variables_initiate),
                        get_mean(&benchmark_variables_responder),
                        get_mean(&benchmark_variables_protocol));

                fclose(fpt);

                snprintf(buf, sizeof(buf),
                         "../results/KEM_SIG/"
                         "variance_cycles_KEM_SIG_NIST_level_%d.csv",
                         requested_NIST_security_level);
                fpt = fopen(buf, "a");

                k = 0;
                while (get_name_KEM(i)[k] != '\0') {
                    fprintf(fpt, "%c", get_name_KEM(i)[k]);
                    ++k;
                }
                fprintf(fpt, " + ");
                k = 0;
                while (get_name_SIG(j)[k] != '\0') {
                    fprintf(fpt, "%c", get_name_SIG(j)[k]);
                    ++k;
                }
                fprintf(fpt, ",");

                fprintf(fpt, "%.0f,%.0f,%.0f,%.0f,%.0f,%.0f,%.0f,%.0f\n",
                        get_variance(&benchmark_variables_white_noise),
                        get_variance(&benchmark_variables_initiate_protocol),
                        get_variance(&benchmark_variables_long_term_key),
                        get_variance(&benchmark_variables_static_key),
                        get_variance(&benchmark_variables_one_time_key),
                        get_variance(&benchmark_variables_initiate),
                        get_variance(&benchmark_variables_responder),
                        get_variance(&benchmark_variables_protocol));

                fclose(fpt);

                snprintf(
                    buf, sizeof(buf),
                    "../results/KEM_SIG/stored_bytes_KEM_SIG_NIST_level_%d.csv",
                    requested_NIST_security_level);
                fpt = fopen(buf, "a");

                k = 0;
                while (get_name_KEM(i)[k] != '\0') {
                    fprintf(fpt, "%c", get_name_KEM(i)[k]);
                    ++k;
                }
                fprintf(fpt, " + ");
                k = 0;
                while (get_name_SIG(j)[k] != '\0') {
                    fprintf(fpt, "%c", get_name_SIG(j)[k]);
                    ++k;
                }
                fprintf(fpt, ",");

                fprintf(
                    fpt, "%d,%d,%d,%d,%d,%d\n", long_term_key_stored_data_size,
                    static_key_stored_data_size, one_time_key_stored_data_size,
                    initiator_stored_data_size, responder_stored_data_size,
                    hole_protocol_stored_data_size);

                fclose(fpt);

                snprintf(
                    buf, sizeof(buf),
                    "../results/KEM_SIG/sent_bytes_KEM_SIG_NIST_level_%d.csv",
                    requested_NIST_security_level);
                fpt = fopen(buf, "a");

                k = 0;
                while (get_name_KEM(i)[k] != '\0') {
                    fprintf(fpt, "%c", get_name_KEM(i)[k]);
                    ++k;
                }
                fprintf(fpt, " + ");
                k = 0;
                while (get_name_SIG(j)[k] != '\0') {
                    fprintf(fpt, "%c", get_name_SIG(j)[k]);
                    ++k;
                }
                fprintf(fpt, ",");

                fprintf(fpt, "%d,%d,%d,%d,%d,%d\n",
                        long_term_key_sent_data_size, static_key_sent_data_size,
                        one_time_key_sent_data_size, initiator_sent_data_size,
                        responder_sent_data_size, hole_protocol_sent_data_size);

                fclose(fpt);
            }
        }
    }

    printf("%d errors\n", error_count);

    return 0;
}

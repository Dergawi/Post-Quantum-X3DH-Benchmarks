#include <math.h>
#include <stdint.h>
#include <stdio.h>

#include "../include/header_Benchmark.h"

void reset_benchmark_variables(benchmark_variables *benchmark_variables) {

    benchmark_variables->iterartion_done = 0;
    benchmark_variables->counter_mean = 0;
    benchmark_variables->counter_variance = 0;
    benchmark_variables->cycle_iteration_protocol = 0;
    benchmark_variables->mean_protocol = 0;
    benchmark_variables->variance_protocol = 0;
    benchmark_variables->total_number_iteration = 0;
    benchmark_variables->mean_lower_bound = 0;
    benchmark_variables->mean_upper_bound = 0;
    benchmark_variables->variance_lower_bound = 0;
    benchmark_variables->variance_upper_bound = 0;

    __asm__ __volatile__("CPUID\n\t"
                         "RDTSC\n\t"
                         "mov %%edx, %0\n\t"
                         "mov %%eax, %1\n\t"
                         : "=r"(benchmark_variables->cycles_high),
                           "=r"(benchmark_variables->cycles_low)::"%rax",
                           "%rbx", "%rcx", "%rdx");
    __asm__ __volatile__("CPUID\n\t"
                         "RDTSC\n\t"
                         "CPUID\n\t"
                         "RDTSC\n\t"
                         "mov %%edx, %0\n\t"
                         "mov %%eax, %1\n\t"
                         : "=r"(benchmark_variables->cycles_high),
                           "=r"(benchmark_variables->cycles_low)::"%rax",
                           "%rbx", "%rcx", "%rdx");
    __asm__ __volatile__("CPUID\n\t"
                         "RDTSC\n\t" ::
                             : "%rax", "%rbx", "%rcx", "%rdx");

    return;
}

void start_benchmark(benchmark_variables *benchmark_variables) {

    __asm__ __volatile__("CPUID\n\t"
                         "RDTSC\n\t"
                         "mov %%edx, %0\n\t"
                         "mov %%eax, %1\n\t"
                         : "=r"(benchmark_variables->cycles_high),
                           "=r"(benchmark_variables->cycles_low)::"%rax",
                           "%rbx", "%rcx", "%rdx");

    return;
}

void end_benchmark(benchmark_variables *benchmark_variables) {

    __asm__ __volatile__("CPUID\n\t"
                         "RDTSC\n\t"
                         "mov %%edx, %0\n\t"
                         "mov %%eax, %1\n\t"
                         : "=r"(benchmark_variables->cycles_high1),
                           "=r"(benchmark_variables->cycles_low1)::"%rax",
                           "%rbx", "%rcx", "%rdx");
    uint64_t start, end;

    benchmark_variables->total_number_iteration++;
    start = (((uint64_t)benchmark_variables->cycles_high << 32) |
             benchmark_variables->cycles_low);
    end = (((uint64_t)benchmark_variables->cycles_high1 << 32) |
           benchmark_variables->cycles_low1);
    benchmark_variables->cycle_iteration_protocol = (double)end - start;
    benchmark_variables->variance_protocol =
        benchmark_variables->variance_protocol +
        ((benchmark_variables->cycle_iteration_protocol -
          benchmark_variables->mean_protocol) *
             (benchmark_variables->cycle_iteration_protocol -
              benchmark_variables->mean_protocol +
              (benchmark_variables->cycle_iteration_protocol -
               benchmark_variables->mean_protocol) /
                  benchmark_variables->total_number_iteration) -
         benchmark_variables->variance_protocol) /
            benchmark_variables->total_number_iteration;
    benchmark_variables->mean_protocol =
        benchmark_variables->mean_protocol +
        (benchmark_variables->cycle_iteration_protocol -
         benchmark_variables->mean_protocol) /
            benchmark_variables->total_number_iteration;

    if ((benchmark_variables->counter_mean < 100) ||
        (benchmark_variables->counter_variance < 100)) {
        if ((benchmark_variables->mean_lower_bound <
             benchmark_variables->mean_protocol) &&
            (benchmark_variables->mean_protocol <
             benchmark_variables->mean_upper_bound)) {
            benchmark_variables->counter_mean++;
            if ((benchmark_variables->variance_lower_bound <
                 sqrt(benchmark_variables->variance_protocol)) &&
                (sqrt(benchmark_variables->variance_protocol) <
                 benchmark_variables->variance_upper_bound)) {
                benchmark_variables->counter_variance++;
            } else {
                benchmark_variables->counter_variance = 0;
                benchmark_variables->variance_lower_bound =
                    sqrt(benchmark_variables->variance_protocol) * 0.95;
                benchmark_variables->variance_upper_bound =
                    sqrt(benchmark_variables->variance_protocol) * 1.05;
            }
        } else {
            benchmark_variables->counter_mean = 0;
            benchmark_variables->counter_variance = 0;
            benchmark_variables->mean_lower_bound =
                benchmark_variables->mean_protocol * 0.95;
            benchmark_variables->mean_upper_bound =
                benchmark_variables->mean_protocol * 1.05;
        }
    } else {
        if (benchmark_variables->iterartion_done == 0) {
            fprintf(stderr, "done\n");
            benchmark_variables->iterartion_done = 1;
        }
    }

    return;
}

double get_mean(benchmark_variables *benchmark_variables) {
    return benchmark_variables->mean_protocol;
}

double get_variance(benchmark_variables *benchmark_variables) {
    return sqrt(benchmark_variables->variance_protocol);
}

int is_done(benchmark_variables *benchmark_variables) {
    return benchmark_variables->iterartion_done;
}

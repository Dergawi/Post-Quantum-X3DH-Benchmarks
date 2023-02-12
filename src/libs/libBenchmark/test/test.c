#include <stdio.h>

#include "../include/header_Benchmark.h"

int main() {

    benchmark_variables benchmark_variables_addition;
    reset_benchmark_variables(&benchmark_variables_addition);

    while (is_done(&benchmark_variables_addition) == 0) {

        start_benchmark(&benchmark_variables_addition);

        int i = 2 + 2;

        end_benchmark(&benchmark_variables_addition);
    }

    printf("The opertation 2 + 2 takes: %15.0f mean cycles %15.0f cycles "
           "variance\n",
           get_mean(&benchmark_variables_addition),
           get_variance(&benchmark_variables_addition));

    return 0;
}

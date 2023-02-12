typedef struct benchmark_variables {
    unsigned cycles_low, cycles_high, cycles_low1, cycles_high1;
    int iterartion_done;
    int counter_mean;
    int counter_variance;
    int total_number_iteration;
    double cycle_iteration_protocol;
    double mean_protocol;
    double variance_protocol;
    double mean_lower_bound;
    double mean_upper_bound;
    double variance_lower_bound;
    double variance_upper_bound;
} benchmark_variables;

void reset_benchmark_variables(benchmark_variables *benchmark_variables);

void start_benchmark(benchmark_variables *benchmark_variables);

void end_benchmark(benchmark_variables *benchmark_variables);

double get_mean(benchmark_variables *benchmark_variables);

double get_variance(benchmark_variables *benchmark_variables);

int is_done(benchmark_variables *benchmark_variables);
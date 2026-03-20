// src/benchmark.c
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/resource.h>

// Declaração da função gerada pelo m2cgen (dentro do iot_model.c)
void score(double * input, double * output);

// Função auxiliar para imprimir números com separador de milhar (ex: 8,187,842)
void print_with_commas(long n) {
    if (n < 1000) {
        printf("%ld", n);
        return;
    }
    print_with_commas(n / 1000);
    printf(",%03ld", n % 1000);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Uso: %s <num_iteracoes>\n", argv[0]);
        return 1;
    }

    long iterations = atol(argv[1]);
    printf("\n🧪 IoT-Shield: Benchmark C-Native (Hardware + Performance)\n");
    printf("⚙️ Iterações alvo: ");
    print_with_commas(iterations);
    printf("\n\n");

    // As nossas 9 Features do modelo
    double input[9] = {1500.0, 1460.0, 64.0, 1.0, 0.0, 0.0, 65535.0, 24.0, 0.15};
    double output[2]; 

    clock_t start = clock();

    // Loop de estresse do TinyML
    for (long i = 0; i < iterations; i++) {
        input[8] = (double)(i % 100) / 100.0; 
        score(input, output); 
    }

    clock_t end = clock();
    double time_spent = (double)(end - start) / CLOCKS_PER_SEC;

    // --- Medição do Consumo de RAM (RSS) ---
    struct rusage r_usage;
    getrusage(RUSAGE_SELF, &r_usage);
    double max_ram_mb = (double)(r_usage.ru_maxrss) / 1024.0;

    // --- Cálculos de Performance ---
    double latency_ms = 0.0;
    long throughput = 0;
    if (time_spent > 0) {
        latency_ms = (time_spent / iterations) * 1000.0;
        throughput = (long)(iterations / time_spent);
    }

    // --- Saída idêntica ao Python ---
    printf("==================================================\n");
    printf("📊 RESULTADOS DO BENCHMARK (C-NATIVE - HARDWARE)\n");
    printf("==================================================\n");
    printf("📁 Consumo de RAM do Modelo: %.2f MB\n", max_ram_mb);
    printf("⏱️ Tempo de Execução:        %.4f segundos\n", time_spent);
    printf("⚡ Latência Média p/ Pacote: %.6f ms\n", latency_ms);
    printf("🚀 Throughput Estimado:      ");
    print_with_commas(throughput);
    printf(" pacotes/s\n");
    printf("==================================================\n");

    return 0;
}
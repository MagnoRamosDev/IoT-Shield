// src/benchmark.c
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/resource.h>
#include <sys/time.h>

// A função gerada pelo m2cgen geralmente se chama 'score' e recebe um array de double
// Certifique-se de que a assinatura aqui bate com o que o m2cgen gerou no iot_model.c
extern double score(double * input); 

int main(int argc, char *argv[]) {
    // Padrão de 50 milhões, mas pode ser sobrescrito pelo terminal
    long iterations = 50000000; 
    
    if (argc > 1) {
        iterations = atol(argv[1]);
    }

    struct rusage usage;
    struct timeval start, end;
    volatile double target; // Evita que o compilador ignore o loop na otimização -O3

    printf("🧪 IoT-Shield: Benchmark C-Native (Hardware + Performance)\n");
    printf("⚙️ Iterações alvo: %ld\n\n", iterations);

    // Array simulando as 9 features extraídas do pacote de rede
    double dummy_packet[9] = {64.0, 0.05, 512.0, 0.0, 1.0, 40.0, 60.0, 2.0, 0.0};

    gettimeofday(&start, NULL);

    for (long i = 0; i < iterations; i++) {
        // Chamando o modelo transpilado
        target = score(dummy_packet);
    }

    gettimeofday(&end, NULL);
    getrusage(RUSAGE_SELF, &usage);

    // Cálculos de Performance
    double time_taken = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec) / 1e6;
    double throughput = iterations / time_taken;
    double latency_ns = (time_taken / iterations) * 1e9;
    double ram_mb = (double)usage.ru_maxrss / 1024.0; 

    printf("====================================================\n");
    printf("📊 FINAL BENCHMARK REPORT (C-NATIVE)\n");
    printf("====================================================\n");
    printf("⏱️ Tempo de Execução:    %.4f segundos\n", time_taken);
    printf("🚀 Throughput:           %.0f pacotes/segundo\n", throughput);
    printf("⚡ Latência Média:       %.2f nanosegundos (ns)\n", latency_ns);
    printf("🧠 Pico de Uso de RAM:   %.2f MB\n", ram_mb);
    printf("====================================================\n");

    return 0;
}
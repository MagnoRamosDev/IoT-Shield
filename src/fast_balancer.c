// src/fast_balancer.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

// Remove quebras de linha invisíveis que podem quebrar a leitura do CSV
void trim_newline(char *str) {
    int len = strlen(str);
    while(len > 0 && (str[len-1] == '\n' || str[len-1] == '\r' || str[len-1] == ' ')) {
        str[len-1] = '\0';
        len--;
    }
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        printf("Uso: %s <input.csv> <output.csv> [ratio]\n", argv[0]);
        return 1;
    }
    
    char *input_file = argv[1];
    char *output_file = argv[2];
    double ratio = (argc >= 4) ? atof(argv[3]) : 1.0;

    FILE *in = fopen(input_file, "r");
    if (!in) { perror("Erro ao abrir arquivo de entrada"); return 1; }

    char buffer[4096];
    long count_0 = 0, count_1 = 0;

    // Pula o cabeçalho na contagem
    if (!fgets(buffer, sizeof(buffer), in)) { fclose(in); return 1; }

    // PASSO 1: Descobrir a proporção exata das classes
    while (fgets(buffer, sizeof(buffer), in)) {
        trim_newline(buffer);
        int len = strlen(buffer);
        if (len == 0) continue;
        
        char label = buffer[len-1];
        if (label == '0') count_0++;
        else if (label == '1') count_1++;
    }

    long target_0 = count_0;
    long target_1 = count_1;
    double prob_0 = 1.0, prob_1 = 1.0;

    // Calcula a probabilidade de manter a linha da classe majoritária
    if (count_0 > 0 && count_1 > 0) {
        if (count_0 > count_1) { // Mais benignos que malignos
            target_0 = (long)(count_1 * ratio);
            if (target_0 > count_0) target_0 = count_0;
            prob_0 = (double)target_0 / count_0;
        } else if (count_1 > count_0) { // Mais malignos que benignos (Cenário Mirai)
            target_1 = (long)(count_0 * ratio);
            if (target_1 > count_1) target_1 = count_1;
            prob_1 = (double)target_1 / count_1;
        }
    }

    rewind(in); // Volta o arquivo para o começo
    FILE *out = fopen(output_file, "w");
    
    // Escreve o cabeçalho no novo arquivo
    fgets(buffer, sizeof(buffer), in);
    fputs(buffer, out);

    srand((unsigned int)time(NULL));
    long wrote_0 = 0, wrote_1 = 0;

    // PASSO 2: Escrever o novo CSV jogando o dado probabilístico
    while (fgets(buffer, sizeof(buffer), in)) {
        char temp[4096];
        strcpy(temp, buffer);
        trim_newline(temp);
        int len = strlen(temp);
        if (len == 0) continue;
        
        char label = temp[len-1];

        if (label == '0') {
            if (prob_0 >= 1.0 || ((double)rand() / RAND_MAX) <= prob_0) {
                fputs(buffer, out);
                wrote_0++;
            }
        } else if (label == '1') {
            if (prob_1 >= 1.0 || ((double)rand() / RAND_MAX) <= prob_1) {
                fputs(buffer, out);
                wrote_1++;
            }
        } else {
            fputs(buffer, out); // Fallback de segurança para não corromper o arquivo
        }
    }

    fclose(in);
    fclose(out);
    
    printf("   ├─ Original:   Benignos: %ld | Malignos: %ld\n", count_0, count_1);
    printf("   └─ Balanceado: Benignos: %ld | Malignos: %ld\n", wrote_0, wrote_1);
    
    return 0;
}
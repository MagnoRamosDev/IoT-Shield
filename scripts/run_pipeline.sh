#!/bin/bash

# Cores para o terminal
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}=========================================================${NC}"
echo -e "${GREEN}🛡️  IoT-Shield: Unified Master Pipeline (Modular)${NC}"
echo -e "${GREEN}=========================================================${NC}\n"

# Garante que a execução ocorra na raiz do projeto (iot-shield/)
cd "$(dirname "$0")/.." || exit

# Ativar Ambiente Virtual
if [ -d ".venv" ]; then
    echo -e "${BLUE}[INFO] Ativando ambiente virtual...${NC}\n"
    source .venv/bin/activate
else
    echo -e "${RED}[ERROR] Ambiente virtual não encontrado na raiz. Rode o setup.sh primeiro.${NC}"
    exit 1
fi

# Configurações Padrão (ML)
ESTIMATORS=15
DEPTH=8
MODEL_PATH="results/iot_shield_model.pkl"
C_MODEL_PATH="results/iot_model.c"

# Configurações Padrão (Data Science / EDA)
EDA_MB=100

# Flags de Execução
EXTRACT_SEQ=false
EXTRACT_PAR=false
EXTRACT_EDA=false
SAMPLE_EDA=false
ANALYZE_EDA=false
USE_FULL_EDA=false
TRAIN=false
EXPORT=false
BENCHMARK=false

show_help() {
    echo -e "Uso: ./scripts/run_pipeline.sh [OPÇÕES]"
    echo -e "\nOpções de Extração (PCAP -> CSV):"
    echo -e "  --extract-seq      Extração sequencial (Baixo uso de RAM)"
    echo -e "  --extract-par      Extração paralela (Mais rápido, Alto uso de RAM)"
    echo -e "  --extract-eda      Extração profunda (Hex/Completa) separada para Ciência de Dados"
    
    echo -e "\nOpções de Ciência de Dados (EDA):"
    echo -e "  --sample-eda       Gera uma amostra reduzida dos dados extraídos"
    echo -e "  --analyze-eda      Gera gráficos e relatórios de assinaturas correlacionadas"
    echo -e "  --mb <N>           Tamanho alvo em MB para a amostragem (Padrão: 100)"
    echo -e "  --use-full-eda     Força a análise a usar a base de dados GIGANTE original (Ignora a amostra)"
    
    echo -e "\nOpções de Machine Learning:"
    echo -e "  --train            Treina o modelo ML e gera gráficos de avaliação"
    echo -e "  --export           Converte o modelo para código C nativo"
    echo -e "  --benchmark        Roda os benchmarks de performance (Python e C)"
    echo -e "  --estimators <N>   Número de árvores (Padrão: 15)"
    echo -e "  --depth <N>        Profundidade máxima (Padrão: 8)"
    
    echo -e "\nComandos Macro (Pipelines Completos):"
    echo -e "  --data-science     Executa: Extração EDA -> Amostragem -> Análise"
    echo -e "  --pipeline         Executa: Treino -> Exportação -> Benchmark (Pula extração)"
    echo -e "  --full             Executa: Extração Paralela -> Treino -> Exportação -> Benchmark"
    echo -e "  --help             Mostra este menu de ajuda\n"
    exit 0
}

if [ "$#" -eq 0 ]; then
    echo -e "${YELLOW}[WARNING] Nenhum parâmetro fornecido. Exibindo menu de ajuda:${NC}\n"
    show_help
fi

# Parse de Argumentos
while [[ "$#" -gt 0 ]]; do
    case $1 in
        # Extração
        --extract-seq) EXTRACT_SEQ=true; shift ;;
        --extract-par) EXTRACT_PAR=true; shift ;;
        --extract-eda) EXTRACT_EDA=true; shift ;;
        
        # Data Science
        --sample-eda) SAMPLE_EDA=true; shift ;;
        --analyze-eda) ANALYZE_EDA=true; shift ;;
        --mb) EDA_MB="$2"; shift 2 ;;
        --use-full-eda) USE_FULL_EDA=true; shift ;;
        --data-science) EXTRACT_EDA=true; SAMPLE_EDA=true; ANALYZE_EDA=true; shift ;;
        
        # Machine Learning
        --train) TRAIN=true; shift ;;
        --export) EXPORT=true; shift ;;
        --benchmark) BENCHMARK=true; shift ;;
        --estimators) ESTIMATORS="$2"; shift 2 ;;
        --depth) DEPTH="$2"; shift 2 ;;
        
        # Macros
        --pipeline) TRAIN=true; EXPORT=true; BENCHMARK=true; shift ;;
        --full) EXTRACT_PAR=true; TRAIN=true; EXPORT=true; BENCHMARK=true; shift ;;
        
        --help) show_help ;;
        *) echo -e "${RED}[ERROR] Parâmetro desconhecido: $1${NC}"; show_help ;;
    esac
done

# ==============================================================================
# BLOCO 0: PREPARAÇÃO DE DADOS
# ==============================================================================

# --- FASE 0.1: EXTRAÇÃO LEVE (TINYML) ---
if [ "$EXTRACT_SEQ" = true ] || [ "$EXTRACT_PAR" = true ]; then
    echo -e "${YELLOW}>>> FASE 0.1: EXTRAÇÃO DE DATASETS (TINYML) <<<${NC}"
    mkdir -p data/datasets/train data/datasets/test

    if [ "$EXTRACT_PAR" = true ]; then
        echo -e "${BLUE}[INFO] Iniciando extração PARALELA...${NC}"
        python src/extractor.py --mode ml -i data/pcaps/Mirai_34-1/2018-12-21-15-50-14-192.168.1.195.pcap -o data/datasets/train/mirai_34_1_train.csv -t 192.168.1.195 &
        python src/extractor.py --mode ml -i data/pcaps/Mirai_43-1/2019-01-10-19-22-51-192.168.1.198.pcap -o data/datasets/train/mirai_43_1_train.csv -t 192.168.1.198 &
        python src/extractor.py --mode ml -i data/pcaps/Mirai_44-1/2019-01-10-21-06-26-192.168.1.199.pcap -o data/datasets/test/mirai_44_1_test.csv -t 192.168.1.199 &
        python src/extractor.py --mode ml -i data/pcaps/Mirai_49-1/2019-02-28-20-50-15-192.168.1.193.pcap -o data/datasets/train/mirai_49_1_train.csv -t 192.168.1.193 &
        python src/extractor.py --mode ml -i data/pcaps/Mirai_52-1/2019-03-08-13-24-30-192.168.1.197.pcap -o data/datasets/test/mirai_52_1_test.csv -t 192.168.1.197 &
        wait
    else
        echo -e "${BLUE}[INFO] Iniciando extração SEQUENCIAL...${NC}"
        python src/extractor.py --mode ml -i data/pcaps/Mirai_34-1/2018-12-21-15-50-14-192.168.1.195.pcap -o data/datasets/train/mirai_34_1_train.csv -t 192.168.1.195
        python src/extractor.py --mode ml -i data/pcaps/Mirai_43-1/2019-01-10-19-22-51-192.168.1.198.pcap -o data/datasets/train/mirai_43_1_train.csv -t 192.168.1.198
        python src/extractor.py --mode ml -i data/pcaps/Mirai_44-1/2019-01-10-21-06-26-192.168.1.199.pcap -o data/datasets/test/mirai_44_1_test.csv -t 192.168.1.199
        python src/extractor.py --mode ml -i data/pcaps/Mirai_49-1/2019-02-28-20-50-15-192.168.1.193.pcap -o data/datasets/train/mirai_49_1_train.csv -t 192.168.1.193
        python src/extractor.py --mode ml -i data/pcaps/Mirai_52-1/2019-03-08-13-24-30-192.168.1.197.pcap -o data/datasets/test/mirai_52_1_test.csv -t 192.168.1.197
    fi
    echo -e "${GREEN}[SUCCESS] Fase de extração TinyML concluída.\n${NC}"
fi

# --- FASE 0.2: EXTRAÇÃO PROFUNDA (EDA) ---
if [ "$EXTRACT_EDA" = true ]; then
    echo -e "${YELLOW}>>> FASE 0.2: EXTRAÇÃO PROFUNDA (BENIGNOS/MALIGNOS) <<<${NC}"
    mkdir -p data/datasets/eda
    
    echo -e "${BLUE}[INFO] Iniciando extração profunda PARALELA para EDA...${NC}"
    python src/extractor.py --mode eda -i data/pcaps/Mirai_34-1/2018-12-21-15-50-14-192.168.1.195.pcap -o data/datasets/eda -t 192.168.1.195 &
    python src/extractor.py --mode eda -i data/pcaps/Mirai_43-1/2019-01-10-19-22-51-192.168.1.198.pcap -o data/datasets/eda -t 192.168.1.198 &
    python src/extractor.py --mode eda -i data/pcaps/Mirai_44-1/2019-01-10-21-06-26-192.168.1.199.pcap -o data/datasets/eda -t 192.168.1.199 &
    python src/extractor.py --mode eda -i data/pcaps/Mirai_49-1/2019-02-28-20-50-15-192.168.1.193.pcap -o data/datasets/eda -t 192.168.1.193 &
    python src/extractor.py --mode eda -i data/pcaps/Mirai_52-1/2019-03-08-13-24-30-192.168.1.197.pcap -o data/datasets/eda -t 192.168.1.197 &
    wait 
    
    echo -e "\n${BLUE}[INFO] Consolidando os arquivos em bases únicas...${NC}"
    python src/data_processor.py --mode merge --dir data/datasets/eda
    echo -e "${GREEN}[SUCCESS] Fase de extração para Data Science (EDA) concluída.\n${NC}"
fi

# --- FASE 0.3: AMOSTRAGEM DE DADOS (EDA) ---
if [ "$SAMPLE_EDA" = true ]; then
    echo -e "${YELLOW}>>> FASE 0.3: AMOSTRAGEM DE DADOS (${EDA_MB} MB) <<<${NC}"
    python src/data_processor.py --mode sample --dir data/datasets/eda --mb $EDA_MB
    echo -e "${GREEN}[SUCCESS] Amostragem concluída com sucesso.\n${NC}"
fi

# --- FASE 0.4: ANÁLISE EXPLORATÓRIA (EDA) ---
if [ "$ANALYZE_EDA" = true ]; then
    echo -e "${YELLOW}>>> FASE 0.4: ANÁLISE EXPLORATÓRIA E CORRELAÇÃO <<<${NC}"
    
    if [ "$USE_FULL_EDA" = true ]; then
        BENIGN_FILE="data/datasets/eda/full_benign.csv"
        MALICIOUS_FILE="data/datasets/eda/full_malicious.csv"
        echo -e "${RED}[WARNING] Usando base de dados COMPLETA! Isso exige muita RAM e processamento.${NC}"
    else
        BENIGN_FILE="data/datasets/eda/sample_benign.csv"
        MALICIOUS_FILE="data/datasets/eda/sample_malicious.csv"
        echo -e "${BLUE}[INFO] Usando base de dados AMOSTRADA...${NC}"
    fi

    python src/data_processor.py --mode analyze --benign $BENIGN_FILE --malicious $MALICIOUS_FILE --outdir results/eda_plots
    echo -e "${GREEN}[SUCCESS] Gráficos e Relatório gerados em 'results/eda_plots/'.\n${NC}"
fi

# ==============================================================================
# BLOCO 1: MACHINE LEARNING & DEPLOYMENT
# ==============================================================================

# --- FASE 1: TREINAMENTO E AVALIAÇÃO ---
if [ "$TRAIN" = true ]; then
    echo -e "${YELLOW}>>> FASE 1: TREINAMENTO DO MODELO E AVALIAÇÃO <<<${NC}"
    python src/model_pipeline.py \
        --train-dir data/datasets/train \
        --test-dir data/datasets/test \
        --output $MODEL_PATH \
        --estimators $ESTIMATORS \
        --depth $DEPTH
    echo -e "${GREEN}[SUCCESS] Fase de treinamento e geração de gráficos concluída.\n${NC}"
fi

# --- FASE 2: EXPORTAÇÃO C ---
if [ "$EXPORT" = true ]; then
    echo -e "${YELLOW}>>> FASE 2: TRANSPILAÇÃO PARA C <<<${NC}"
    python src/deploy_tools.py --mode export --model $MODEL_PATH --output-c $C_MODEL_PATH
    echo -e "${GREEN}[SUCCESS] Exportação concluída.\n${NC}"
fi

# --- FASE 3: BENCHMARK ---
if [ "$BENCHMARK" = true ]; then
    echo -e "${YELLOW}>>> FASE 3: BENCHMARK DE HARDWARE <<<${NC}"
    
    echo -e "${BLUE}[INFO] Avaliando modelo no Python...${NC}"
    python src/deploy_tools.py --mode benchmark --model $MODEL_PATH --packets 100000
    
    echo -e "\n${BLUE}[INFO] Compilando e avaliando modelo C...${NC}"
    gcc -O3 -fno-stack-protector src/benchmark.c $C_MODEL_PATH -o results/benchmark_c -lm
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[SUCCESS] Compilação C bem-sucedida! Rodando teste de estresse...${NC}\n"
        ./results/benchmark_c 50000000
    else
        echo -e "${RED}[ERROR] Falha na compilação GCC. Verifique o código gerado.${NC}"
        exit 1
    fi
fi

echo -e "\n${GREEN}=========================================================${NC}"
echo -e "${GREEN}✅ Pipeline finalizado com sucesso!${NC}"
echo -e "${GREEN}=========================================================${NC}"
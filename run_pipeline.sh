#!/bin/bash

# Define colors for terminal output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}=========================================================${NC}"
echo -e "${GREEN}🛡️  IoT-Shield: Unified Master Pipeline${NC}"
echo -e "${GREEN}=========================================================${NC}\n"

# 2. Activate Virtual Environment
if [ -d ".venv" ]; then
    echo -e "${BLUE}[INFO] Activating virtual environment...${NC}\n"
    source .venv/bin/activate
else
    echo -e "${RED}[ERROR] Virtual environment not found. Please run setup.sh first.${NC}"
    exit 1
fi

# 3. Parameter Parsing
EXTRACT_SEQ=false
EXTRACT_PAR=false
TRAIN=false
EXPORT=false
BENCHMARK=false

show_help() {
    echo -e "Usage: run_pipeline.sh [OPTIONS]"
    echo -e "\nExtraction Options:"
    echo -e "  --extract-seq  Run feature extraction sequentially (Low RAM usage)"
    echo -e "  --extract-par  Run feature extraction in parallel (Fastest, High RAM usage)"
    echo -e "\nSingle Module Execution:"
    echo -e "  --train        Run ML training and generate academic plots ONLY"
    echo -e "  --export       Convert the trained model to Native C code ONLY"
    echo -e "  --benchmark    Run Python and C hardware performance benchmarks ONLY"
    echo -e "\nMacro Commands (Combinations):"
    echo -e "  --eval         Run Export -> Benchmark (Skips training)"
    echo -e "  --pipeline     Run Train -> Export -> Benchmark (Skips extraction)"
    echo -e "  --full         Run Extract (Parallel) -> Train -> Export -> Benchmark"
    echo -e "  --help         Show this help message\n"
    exit 0
}

if [ "$#" -eq 0 ]; then
    echo -e "${YELLOW}[WARNING] No parameters provided. Displaying help menu:${NC}\n"
    show_help
fi

for arg in "$@"; do
    case $arg in
        --extract-seq) EXTRACT_SEQ=true ;;
        --extract-par) EXTRACT_PAR=true ;;
        --train) TRAIN=true ;;
        --export) EXPORT=true ;;
        --benchmark) BENCHMARK=true ;;
        --eval) EXPORT=true; BENCHMARK=true ;;
        --pipeline) TRAIN=true; EXPORT=true; BENCHMARK=true ;;
        --full) EXTRACT_PAR=true; TRAIN=true; EXPORT=true; BENCHMARK=true ;;
        --help) show_help ;;
        *) echo -e "${RED}[ERROR] Unknown parameter: $arg${NC}"; show_help ;;
    esac
done

# 4. Execution Blocks

# --- EXTRACTION PHASE ---
if [ "$EXTRACT_SEQ" = true ] || [ "$EXTRACT_PAR" = true ]; then
    echo -e "${YELLOW}>>> PHASE 0: DATASET EXTRACTION <<<${NC}"
    
    # Ensure directories exist
    mkdir -p data/datasets/train
    mkdir -p data/datasets/test

    if [ "$EXTRACT_PAR" = true ]; then
        echo -e "${BLUE}[INFO] Starting PARALLEL extraction (Dispatching background tasks)...${NC}"
        python src/pcap_reader.py -i data/pcaps/Mirai_34-1/2018-12-21-15-50-14-192.168.1.195.pcap -o data/datasets/train/mirai_34_1_train.csv -t 192.168.1.195 &
        python src/pcap_reader.py -i data/pcaps/Mirai_43-1/2019-01-10-19-22-51-192.168.1.198.pcap -o data/datasets/train/mirai_43_1_train.csv -t 192.168.1.198 &
        python src/pcap_reader.py -i data/pcaps/Mirai_52-1/2019-03-08-13-24-30-192.168.1.197.pcap -o data/datasets/train/mirai_52_1_train.csv -t 192.168.1.197 &
        python src/pcap_reader.py -i data/pcaps/Mirai_44-1/2019-01-10-21-06-26-192.168.1.199.pcap -o data/datasets/test/mirai_44_1_test.csv -t 192.168.1.199 &
        python src/pcap_reader.py -i data/pcaps/Mirai_49-1/2019-02-28-20-50-15-192.168.1.193.pcap -o data/datasets/test/mirai_49_1_test.csv -t 192.168.1.193 &
        
        # Wait for all background tasks to finish
        wait
    else
        echo -e "${BLUE}[INFO] Starting SEQUENTIAL extraction...${NC}"
        python src/pcap_reader.py -i data/pcaps/Mirai_34-1/2018-12-21-15-50-14-192.168.1.195.pcap -o data/datasets/train/mirai_34_1_train.csv -t 192.168.1.195
        python src/pcap_reader.py -i data/pcaps/Mirai_43-1/2019-01-10-19-22-51-192.168.1.198.pcap -o data/datasets/train/mirai_43_1_train.csv -t 192.168.1.198
        python src/pcap_reader.py -i data/pcaps/Mirai_52-1/2019-03-08-13-24-30-192.168.1.197.pcap -o data/datasets/train/mirai_52_1_train.csv -t 192.168.1.197
        python src/pcap_reader.py -i data/pcaps/Mirai_44-1/2019-01-10-21-06-26-192.168.1.199.pcap -o data/datasets/test/mirai_44_1_test.csv -t 192.168.1.199
        python src/pcap_reader.py -i data/pcaps/Mirai_49-1/2019-02-28-20-50-15-192.168.1.193.pcap -o data/datasets/test/mirai_49_1_test.csv -t 192.168.1.193
    fi
    echo -e "${GREEN}[SUCCESS] Extraction phase completed.\n${NC}"
fi

# --- TRAIN PHASE ---
if [ "$TRAIN" = true ]; then
    echo -e "${YELLOW}>>> PHASE 1: MODEL TRAINING & PLOTTING <<<${NC}"
    echo -e "${BLUE}[INFO] Executing Random Forest Training...${NC}"
    python src/trainer_pipeline.py
    
    echo -e "\n${BLUE}[INFO] Generating Academic Visualizations...${NC}"
    python src/generate_graphs.py
    echo -e "${GREEN}[SUCCESS] Training phase completed.\n${NC}"
fi

# --- EXPORT PHASE ---
if [ "$EXPORT" = true ]; then
    echo -e "${YELLOW}>>> PHASE 2: C-CODE TRANSPILATION <<<${NC}"
    echo -e "${BLUE}[INFO] Exporting model to Native C...${NC}"
    python src/export_to_c.py
    echo -e "${GREEN}[SUCCESS] Export phase completed.\n${NC}"
fi

# --- BENCHMARK PHASE ---
if [ "$BENCHMARK" = true ]; then
    echo -e "${YELLOW}>>> PHASE 3: PERFORMANCE BENCHMARKING <<<${NC}"
    
    echo -e "${BLUE}[INFO] Running Python Software Benchmark...${NC}"
    python src/benchmark_model.py
    
    echo -e "\n${BLUE}[INFO] Compiling C-Native Benchmark...${NC}"
    mkdir -p results
    gcc -O3 -fno-stack-protector src/benchmark.c results/iot_model.c -o results/benchmark_c -lm
    
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[SUCCESS] Compilation successful. Executing Hardware Benchmark...${NC}\n"
        ./results/benchmark_c
    else
        echo -e "${RED}[ERROR] GCC Compilation failed. Ensure the C model was exported correctly.${NC}"
        exit 1
    fi
fi

echo -e "\n${GREEN}=========================================================${NC}"
echo -e "${GREEN}✅ Pipeline execution finished successfully!${NC}"
echo -e "${GREEN}=========================================================${NC}"
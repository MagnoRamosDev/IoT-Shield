# 🛡️ IoT-Shield: TinyML Edge Detection for IoT Malware

> **Undergraduate Research Project (PIBIC)**
> 
> An architecture for detecting malware (Botnets such as Mirai and Bashlite) in Internet of Things (IoT) devices with extreme resource constraints, utilizing Artificial Intelligence at the edge (_Edge AI / TinyML_).

## 📖 Project Overview

**IoT-Shield** proposes a network anomaly-based cybersecurity approach (NIDS) specifically designed for the IoT ecosystem. Given that the majority of these devices lack the CPU and memory resources required to run traditional antivirus software, this project focuses on ultra-fast network feature extraction (via `dpkt`) and the application of a lightweight AI model (optimized Random Forest).

The primary technological differentiator of this research is the transpilation of the trained AI model (developed in Python) into pure **Native C Code** (via `m2cgen`). This enables real-time inference directly on microcontrollers and embedded devices without relying on resource-intensive libraries.

## 🏗️ Repository Architecture

The project adopts a modular structure to separate concerns effectively (Data, Scripts, Source, and Results):

```
IoT-Shield/
├── README.md                    # Main project documentation
├── setup.sh                     # Automated environment and dependency installation
├── data/                        # Data directory (Not versioned in Git)
│   ├── pcaps/                   # Raw captured network traffic files (.pcap)
│   └── datasets/                # Generated CSVs post-feature extraction
│       ├── train/               # Training dataset
│       └── test/                # Zero-Day evaluation dataset
├── src/                         # Main source code
│   ├── pcap_reader.py           # Network feature extractor (Stateless/dpkt)
│   ├── experiment_runner.py     # ML training pipeline (Scikit-Learn)
│   ├── generate_graphs.py       # Academic plot generator for publications
│   ├── export_to_c.py           # AI to Native C transpiler (m2cgen)
│   ├── benchmark_model.py       # Software metrics validator (Python)
│   └── benchmark.c              # Hardware performance validator (C)
├── scripts/                     # Bash CLI automations
│   └── run_pipeline.sh          # Master Script (Unified Command Line Interface)
└── results/                     # Automatically generated final artifacts
    ├── iot_shield_model.pkl     # Frozen trained model
    ├── iot_model.c              # Transpiled AI rules in C
    ├── benchmark_c              # Compiled hardware test binary
    └── *.png                    # Evaluation plots

```

## ⚙️ Prerequisites and Installation

The project features an automated script that prepares the entire operating system (Linux/Ubuntu), installs compilation dependencies (GCC), and configures the Python virtual environment.

**1. Clone the repository and navigate to the root directory:**

```
git clone [https://github.com/your-username/IoT-Shield.git](https://github.com/your-username/IoT-Shield.git)
cd IoT-Shield

```

**2. Grant execution permissions and run the setup script:**

```
chmod +x setup.sh scripts/run_pipeline.sh
./setup.sh

```

**3. Reload terminal group permissions (Mandatory for Wireshark/tshark):**

```
source .venv/bin/activate
newgrp wireshark

```

## 🚀 Usage (CLI Interface)

The entire research workflow, from raw data extraction to hardware validation, has been consolidated into a single _Master Script_ (`run_pipeline.sh`), facilitating the seamless reproducibility of the scientific experiments.

### Fully Automated Execution

To execute the entire research pipeline from scratch (extract data, train, export, and benchmark):

```
./scripts/run_pipeline.sh --full

```

### Granular Execution (Individual Modules)

You can execute specific phases of the research using the following flags:

- **`--extract-par`**: Fast parallel extraction (high RAM usage).
    
- **`--extract-seq`**: Sequential extraction (low RAM usage).
    
- **`--train`**: Run ML training and generate academic plots only.
    
- **`--export`**: Convert the trained model to Native C code only.
    
- **`--benchmark`**: Run Python and C hardware performance benchmarks only.
    
- **`--eval`**: Run Export -> Benchmark (skips training).
    
- **`--pipeline`**: Run Train -> Export -> Benchmark (skips extraction).
    

## 🔬 Academic Experiment Phases

1. **Feature Extraction (dpkt):** Processing massive `.pcap` files via _stateless parsing_, extracting 9 vital variables from the network and transport layers.
    
2. **Training and Balancing (Random Forest):** Partitioned reading (in _chunks_) with statistical _undersampling_ of the majority class to prevent _overfitting_.
    
3. **TinyML Transpilation:** Translating the trained decision tree directly into the logical syntax of the C language (`if/else` structures).
    
4. **Hardware Benchmarking:** Conducting stress tests against the native C logic to verify throughput (Gbps) with nanosecond latency.
    

## 📊 Generated Visualizations

The following plots are automatically generated during the training phase and saved in the `results/` directory.

### Feature Importance

Illustrates which network attributes are most critical for the TinyML model.

### Confusion Matrix

Demonstrates the model's accuracy against unseen attack datasets.

## 📚 Dataset Reference

The datasets used in this research are provided by the **IoT-23** project. If you utilize this dataset or repository for your research, please reference it as:

> Sebastian Garcia, Agustin Parmisano, & Maria Jose Erquiaga. (2020). IoT-23: A labeled dataset with malicious and benign IoT network traffic (Version 1.0.0) [Data set]. Zenodo. http://doi.org/10.5281/zenodo.4743746

## 👨‍💻 Authorship and Acknowledgements

- **Author:** Magno Ramos Guimarães
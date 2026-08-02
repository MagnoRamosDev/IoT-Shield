# 🛡️ IoT-Shield: Detecção de Malware IoT em Tempo Real (TinyML/Edge AI)

> **Projeto de Pesquisa / NIDS Leve**
> 
> Uma arquitetura projetada para detectar Botnets (como Mirai e Bashlite) em roteadores e dispositivos de Borda (OpenWRT / Edge) altamente restritos. Para isso, aplicamos Inteligência Artificial leve, convertendo modelos inteiros de Machine Learning para a linguagem C pura!

## 📖 Visão Geral do Projeto

Roteadores domésticos e dispositivos de entrada (hardware com `<= 128MB` de RAM e CPUs debaixo de `1GHz`) sofrem para rodar antivírus tradicionais baseados em assinaturas de rede gigantes.

O **IoT-Shield** moderniza essa defesa! Treinamos um algoritmo *Random Forest* (usando a pesada biblioteca do Python, Scikit-Learn) e **transpilamos a "árvore do conhecimento" nativamente para C via m2cgen**. Aliado a um Sniffer passivo extremamente otimizado (`libpcap`), garantimos detecção de malware super veloz diretamente no núcleo do roteador.

### Benefícios Comprovados na Prática (Benchmark)
* **Memória**: Opera livremente usando entre **3 a 7 Megabytes** de RAM.
* **Latência**: Detecta e computa anomalias de rede em apenas **~1.4 a 5.0 microsegundos** por pacote!
* **Throughput**: Escudo silencioso que consome menos de 3% da CPU do roteador numa casa movimentada.

---

## ⚙️ Instalação e Setup

Antes de clonar o projeto, é obrigatório garantir que o seu sistema operacional possui as ferramentas básicas de compilação e o ecossistema Python instalados.

### 1. Pré-requisitos do Sistema (Linux)

- python3
- python3-venv
- gcc
- libpcap-dev

Se você estiver usando Ubuntu, Debian ou derivados, instale os pacotes essenciais executando:
```bash
sudo apt update
sudo apt install python3 python3-venv gcc libpcap-dev
```

* **python3 e python3-venv:** Necessários para o treinamento da IA e criação do ecossistema isolado.
* **gcc e libpcap-dev:** Necessários para compilar o código C nativo e capturar os pacotes de rede na Fase 4.

### 2. Configurando o Ambiente do IoT-Shield

Com os pré-requisitos instalados, você pode preparar o ecossistema isolado do projeto:

```bash
# 1. Clone o repositório
git clone https://github.com/MagnoRamosDev/IoT-Shield.git
cd IoT-Shield

# 2. Rode o script de instalação (Cria o venv e instala as dependências)
bash scripts/setup.sh
```

---

## 📚 Documentação e Manuais Oficiais

Para aprender a operar todas as etapas (da Extração bruta de `.pcap` à Compilação final em C), consulte os manuais detalhados na pasta `docs/`:

1. **[Treinando a IA (Passo a Passo)](docs/1_TREINAMENTO_IA.md)**: Como popular seus pacotes `.pcap`, usar o Pipeline e rodar o Extrator/Balanceador para chegar à Matriz de Confusão perfeita.
2. **[Usando e Embarcando o Firmware C](docs/2_USANDO_FIRMWARE_C.md)**: Onde exportar, compilar e acionar a sua rede neural (Sniffer.c + Model.c) interceptando malwares em tempo real na rede da sua casa ou laboratório.

---

## 🚀 Interface do Usuário (Pipeline Modular)

A arquitetura do IoT-Shield foca em isolamento. As fases pesadas em processamento e memória evitam congelar o sistema. Para gerenciar tudo, use o orquestrador `./scripts/run.sh`.

```bash
# Fase 1: Converter tráfego .pcap em matrizes numéricas (Features)
./scripts/run.sh --phase extract --max-ram 14000 --workers 14 --split-size 500

# Fase 2: Balancear dados da rede (Undersampling benigno)
./scripts/run.sh --phase balance

# Fase 3: Treinar o cérebro (Random Forest ML)
./scripts/run.sh --phase train --threshold 0.6 --folds 5

# Fase 4: Exportar para C, Benchmark End-to-End e gerar Binário
./scripts/run.sh --phase export

```

## 📊 Estrutura de Diretórios

```text
IoT-Shield/
├── README.md                    # Documentação principal
├── docs/                        # Guias e tutoriais passo-a-passo
├── config/                      
│   └── excluded_features.txt    # Lista de ignorados (Prevenção de Bias IP/MAC)
├── data/                        
│   ├── datasets_list.txt        # Dicionário de caminhos e IPs de Rótulo (Malicioso)
│   └── pcaps/                   # Arquivos brutos de tráfego (Ex: Wireshark)
├── src/                         
│   ├── pipeline.py              # Centralizador de chamadas
│   ├── extractor.py             # Leitor de PCAPs via dpkt (Multipackage)
│   ├── balancer.py              # Processamento de Dados via Amostragem
│   ├── trainer.py               # Motor de ML da Inteligência (Scikit)
│   ├── export_to_c.py           # Transpilador TinyML (m2cgen)
│   ├── dashboard.py             # Renderizador UI (Biblioteca Rich)
│   ├── benchmark.py             # Módulo Avaliador C vs Python
│   └── iot_shield_sniffer.c     # Sniffer Nativo em C (Código Fonte)
├── scripts/                     
│   ├── setup.sh                 # Construtor do ecossistema e dependências
│   └── run.sh                   # Orquestrador Bash / Parametrizador
└── results/                     # Resultados finais gerados pelo sistema
    ├── rf_model.pkl             # IA congelada
    ├── iot_shield_model.c       # IA Transpilada para C
    ├── iot_shield_sniffer.c     # Cópia do Sniffer exportada para compilação
    └── iot_shield_sniffer       # Binário Executável Nativo
```

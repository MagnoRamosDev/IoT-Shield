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

## 📚 Documentação e Manuais Oficiais

Para aprender a operar todas as etapas (da Extração bruta de `.pcap` à Compilação final em C), consulte os manuais detalhados na pasta `docs/`:

1. **[Treinando a IA (Passo a Passo)](docs/1_TREINAMENTO_IA.md)**: Como popular seus pacotes `.pcap`, usar o Pipeline e rodar o Extrator/Balanceador para chegar à Matriz de Confusão perfeita.
2. **[Usando e Embarcando o Firmware C](docs/2_USANDO_FIRMWARE_C.md)**: Onde exportar, compilar e acionar a sua rede neural (Sniffer.c + Model.c) interceptando malwares em tempo real na rede da sua casa ou laboratório.

---

## 🚀 Interface do Usuário (Pipeline Modular)

A arquitetura do IoT-Shield foca em isolamento. As fases pesadas em processamento e memória jamais congelam o sistema graças a quebra de contexto. Para gerenciar tudo, use o orquestrador `./scripts/run.sh`.

```bash
# Fase 1: Converter tráfego .pcap em matrizes numéricas (Features)
./scripts/run.sh --phase extract --max-ram 14000 --workers 14 --split-size 500

# Fase 2: Balancear dados da rede (Undersampling benigno)
./scripts/run.sh --phase balance

# Fase 3: Treinar o cérebro (Random Forest ML)
./scripts/run.sh --phase train --threshold 0.6

# Fase 4: Exportar para o Roteador, fazer Benchmarks End-to-End e gerar Binário
./scripts/run.sh --phase export
```

## 📊 Estrutura de Diretórios

```
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
│   ├── extractor.py             # Leitor de PCAPs via Scapy (Multipackage)
│   ├── balancer.py              # Processamento de Dados via Pandas
│   ├── trainer.py               # Motor de ML da Inteligência (Scikit)
│   ├── export_to_c.py           # Transpilador TinyML (m2cgen)
│   ├── dashboard.py             # Renderizador UI (Biblioteca Rich)
│   └── benchmark.py             # Módulo Avaliador C vs Python
├── scripts/                     
│   └── run.sh                   # Orquestrador Bash / Parametrizador
└── results/                     # Resultados finais gerados pelo sistema
    ├── rf_model.pkl             # IA congelada
    ├── iot_shield_model.c       # IA Transpilada para C
    ├── iot_shield_sniffer.c     # Sniffer Nativo para Gateway (Pcap)
    └── iot_shield_sniffer       # Binário Mágico!
```

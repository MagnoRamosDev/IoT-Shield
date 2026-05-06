# Treinamento da Inteligência Artificial (IoT-Shield)

Este guia explica o passo a passo de como utilizar a arquitetura modular do IoT-Shield para criar a sua própria Inteligência Artificial a partir de pacotes de rede brutos (.pcap). O processo foi automatizado pelo `Dashboard` interativo.

## 📁 1. Preparando os Dados

Antes de rodar a IA, você precisa fornecer o tráfego que ela vai estudar e rotular corretamente os IPs maliciosos. O programa **não** procura arquivos soltos; ele usa um arquivo de mapa como guia central.

1. Insira os seus arquivos `.pcap` ou `.pcapng` em uma pasta de sua escolha (ex: `data/pcaps/`).
2. **PASSO OBRIGATÓRIO**: Edite o arquivo **`data/datasets_list.txt`**. Nele, você deve colocar o caminho relativo de cada `.pcap` seguido de um espaço e do IP do dispositivo infectado (o atacante). 
   - Se o `.pcap` contiver apenas tráfego benigno, use o IP `0.0.0.0` para indicar que tudo ali é seguro.
   - Exemplo do arquivo `datasets_list.txt`:
     ```text
     data/pcaps/Benign/trabalho_normal.pcap 0.0.0.0
     data/pcaps/Mirai/ataque_noturno.pcap 192.168.1.195
     ```
3. Configure a lista de classes editando o arquivo **`config/excluded_features.txt`** caso queira que a IA ignore atributos irrelevantes que possam causar viés (como endereços IP diretos, portas específicas ou MAC address).
   - **Nota:** Por padrão, as features que já vieram excluídas nesse arquivo foram cuidadosamente removidas pensando no treinamento contra vírus do tipo **Botnets** (Mirai, Bashlite, etc), forçando a IA a focar no comportamento do fluxo (Flow Rate, P.I.A.T) em vez de focar nos endereços. Se o seu objetivo for treinar a IA para descobrir outro tipo de ataque, sinta-se livre para escolher suas próprias features!
---

## 🚀 2. O Pipeline de Treinamento

O projeto foi dividido em Fases para que a RAM da sua máquina não estoure. Todo o controle é feito via `./scripts/run.sh`.

### Fase 1: Extração (Extraction)
Esta fase pega os arquivos gigantes de Wireshark (`.pcap`), lê os cabeçalhos Ethernet/IP/TCP/UDP com a biblioteca Scapy e transforma o tráfego de rede em matrizes numéricas (Features).

**Comando:**
```bash
./scripts/run.sh --phase extract --max-ram 14000 --workers 14 --split-size 500
```
- `--max-ram`: Limita o consumo de memória RAM (Ex: 14000 = 14GB).
- `--workers`: Quantos núcleos do processador serão usados em paralelo para ler os PCAPs.
- `--split-size`: Tamanho em MB para dividir arquivos gigantes e evitar travamentos.

**Resultado:** Serão gerados arquivos binários temporários `.npy` otimizados contendo os fluxos brutos.

### Fase 2: Balanceamento (Balancing)
Geralmente temos 90% de tráfego benigno e 10% de vírus (ou vice-versa). Se a IA for treinada assim, ela ficará viciada. Esta fase equaliza matematicamente o peso das classes (Undersampling/SMOTE) para garantir aprendizado justo.

**Comando:**
```bash
./scripts/run.sh --phase balance
```

**Resultado:** É gerado o arquivo `results/balanced_dataset.csv` e `results/test.csv`.

### Fase 3: Treinamento (Training)
Aqui a mágica acontece. O algoritmo de **Random Forest** (Árvore de Decisão) será alimentado com os dados balanceados. 

**Comando:**
```bash
./scripts/run.sh --phase train --threshold 0.6
```
- `--threshold`: (0.0 a 1.0) Ajusta o rigor da detecção. `0.6` significa que a IA só alertará vírus se tiver mais de 60% de certeza absoluta, reduzindo Falsos Positivos.

**Resultado:**
Ao final do treinamento, o Dashboard vai renderizar tabelas maravilhosas na tela contendo:
- A Acurácia da IA e o _Classification Report_.
- A Matriz de Confusão (Acertos vs Erros Reais).
- A **Feature Importance**: O Ranking matemático revelando quais atributos a IA mais usou para descobrir que era vírus (Ex: `syn_to_total_ratio`, `is_constant_payload`).

O modelo inteligente é salvo no arquivo congelado e imutável em: `results/rf_model.pkl`.

---

## 🛠️ O que fazer em caso de erro?
- **Deadlock de Memória:** Caso a _Fase 1_ congele, reduza o número de `--workers` (escolha dependendo da quantidade de núcleos do seu processador, por ex: se tiver 4 núcleos, use 3 ou 2 para deixar 1 ou 2 livres) e reduza `--split-size` para 200.
- Caso precise rodar todas as 3 fases de uma só vez de forma sequencial (Demorado), você pode encadear os comandos usando o Linux (`&&`).

👉 Após treinar sua IA (Fase 3), siga para o manual **[2_USANDO_FIRMWARE_C.md](2_USANDO_FIRMWARE_C.md)** para converter sua IA para Hardware nativo!

# Treinamento da Inteligência Artificial (IoT-Shield)

Este guia explica o passo a passo de como utilizar a arquitetura modular do IoT-Shield para criar a sua própria Inteligência Artificial a partir de pacotes de rede brutos (.pcap). O processo foi automatizado pelo `Dashboard` interativo.

## 📁 1. Preparando os Dados

Antes de rodar a IA, você precisa fornecer o tráfego que ela vai estudar e rotular corretamente os IPs maliciosos. O programa **não** procura arquivos soltos; ele usa um arquivo de mapa como guia central.

1. Insira os seus arquivos `.pcap` ou `.pcapng` em uma pasta de sua escolha (ex: `data/pcaps/`).
2. **PASSO OBRIGATÓRIO**: Crie o arquivo **`data/datasets_list.txt`**. Nele, você deve colocar o caminho relativo de cada `.pcap` seguido de um espaço e do IP do dispositivo infectado (o atacante). 
   - Se o `.pcap` contiver apenas tráfego benigno, use o IP `0.0.0.0` para indicar que tudo ali é seguro.
   - Exemplo do arquivo `datasets_list.txt`:
     ```text
     data/pcaps/Benign/trabalho_normal.pcap 0.0.0.0
     data/pcaps/Mirai/ataque_noturno.pcap 192.168.1.195
     ```
   - **Nota:** Cada linha do arquivo é para uma base de dados diferentes e voce pode colocar quantos quiser, além disso o arquivo não pode conter comentários nem outro tipo de informação fora os dadasets e ips.
3. Configure a lista de classes editando o arquivo **`config/excluded_features.txt`** caso queira que a IA ignore atributos irrelevantes que possam causar viés (como endereços IP diretos, portas específicas ou MAC address).
   - **Nota:** Por padrão, as features que já vieram excluídas nesse arquivo foram cuidadosamente removidas pensando no treinamento contra vírus do tipo **Botnets** (Mirai, Bashlite, etc), forçando a IA a focar no comportamento do fluxo (Flow Rate, P.I.A.T) em vez de focar nos endereços. Se o seu objetivo for treinar a IA para descobrir outro tipo de ataque, sinta-se livre para escolher suas próprias features!

---

## 🚀 2. O Pipeline de Treinamento

O projeto foi dividido em Fases para que a RAM da sua máquina não estoure. Todo o controle é feito via `./scripts/run.sh`.

### Fase 1: Extração (Extraction)
Esta fase pega os arquivos gigantes de Wireshark (`.pcap`), lê os cabeçalhos Ethernet/IP/TCP/UDP com a biblioteca `dpkt` e transforma o tráfego de rede em matrizes numéricas (Features).

**Comando:**
```bash
./scripts/run.sh --phase extract --max-ram 14000 --workers 14 --split-size 500

```

* `--max-ram`: Limita o consumo de memória RAM (Ex: 14000 = 14GB).
* `--workers`: Quantos núcleos do processador serão usados em paralelo para ler os PCAPs.
* `--split-size`: Tamanho em MB para dividir arquivos gigantes e evitar travamentos.

**Resultado:** Serão gerados arquivos binários temporários `.npy` otimizados contendo os fluxos brutos.

### Fase 2: Balanceamento (Balancing)

Geralmente temos 90% de tráfego benigno e 10% de vírus (ou vice-versa). Se a IA for treinada assim, ela ficará viciada. Esta fase equaliza matematicamente o peso das classes (Undersampling por Amostragem Probabilística) para garantir aprendizado justo.

**Comando:**

```bash
./scripts/run.sh --phase balance

```

**Resultado:** Serão gerados os arquivos `results/fold_X.csv` contendo as dobras balanceadas.

> ⚠️ **Aviso Importante para Testes com PCAPs Pequenos**
>
> O IoT-Shield foi arquitetado para processar *Big Data*. Por padrão, o algoritmo de balanceamento exige que existam no mínimo **10.000 fluxos** de um mesmo protocolo/classe para considerá-lo estatisticamente válido para o treinamento.
> 
> Se você utilizar um arquivo `.pcap` muito pequeno (apenas para testes rápidos), a Fase 2 não encontrará fluxos suficientes e será abortada. Como mecanismo de autolimpeza, o sistema deletará a pasta temporária `data/tmp/` para liberar espaço no SSD, e **a pasta `results/` ficará vazia**.
>
> **Como resolver (Modo de Teste):**
> Se você está apenas validando o funcionamento do software com poucos dados, abra o arquivo `src/balancer.py`, localize a variável `MIN_GROUP = 10000` e reduza seu valor (ex: `MIN_GROUP = 1`). Após a alteração, rode a Fase 1 (Extração) novamente, seguida da Fase 2.

### Fase 3: Treinamento (Training)

Aqui a mágica acontece. O algoritmo de **Random Forest** (Árvore de Decisão) será alimentado com os dados balanceados usando Validação Cruzada (Cross-Validation).

**Comando:**

```bash
./scripts/run.sh --phase train --threshold 0.6 --folds 5

```

**Parâmetros Extras (Avançados):**

* `--threshold`: (0.0 a 1.0) Ajusta o rigor da detecção. `0.6` significa que a IA só alertará vírus se tiver mais de 60% de certeza absoluta, reduzindo Falsos Positivos.
* `--folds`: Define quantas dobras terá a Validação Cruzada (Padrão: 5).
* `--exclude-list`: Caminho opcional para passar um arquivo customizado de regras (Ex: `config/minhas_regras.txt`).
* `--dataset-list`: Caminho opcional para processar uma lista customizada de PCAPs.

**Resultados Gerados na Pasta `results/`:**
Além das tabelas maravilhosas no Dashboard, o sistema vai gerar os seguintes arquivos cruciais:

* **`rf_model.pkl`**: O modelo inteligente treinado e congelado em disco.
* **`feature_names.txt`**: A ordem exata das colunas (features) que o modelo utiliza.
* **`misclassified.csv`** *(Muito Importante)*: Uma tabela exportada automaticamente contendo **todos os fluxos exatos que enganaram a IA** durante o teste. Excelente para Análise Forense e calibração fina.
* **`correctly_classified.csv`**: A listagem de fluxos nos quais a IA acertou.

---

## 🛠️ O que fazer em caso de erro?

👉 Após treinar sua IA (Fase 3), siga para o manual **[2_USANDO_FIRMWARE_C.md](2_USANDO_FIRMWARE_C.md)** para converter sua IA para Hardware nativo!

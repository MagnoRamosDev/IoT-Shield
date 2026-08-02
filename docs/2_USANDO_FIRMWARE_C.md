# Firmware C: Exportação e Implantação (IoT-Shield)

Se você já realizou o Treinamento da IA (como descrito no passo anterior e gerou o arquivo `results/rf_model.pkl`), chegou o momento de embarcar sua IA para dispositivos de entrada (Microcontroladores, Roteadores OpenWRT, Gateways de Borda).

O IoT-Shield elimina o peso monstruoso do Python (que consome GBs de RAM) e transforma todo o cérebro da inteligência artificial num binário nativo em C.

---

## ⚡ 1. A Fase de Exportação

A Fase 4 do pipeline se encarrega de aplicar o **Transpilador (m2cgen)**. Ele traduz as Árvores Matemáticas do Random Forest em código C puro (Múltiplos `if`/`else` rígidos em linguagem C) com precisão de *double* point.

**Comando:**
```bash
./scripts/run.sh --phase export

```

**O que este comando faz automaticamente por trás dos panos?**

1. **Transpilação**: Gera o arquivo `results/iot_shield_model.c` contendo a função inteligente matemática `score(double *input, double *output)`. O script exporta também o código base para `results/iot_shield_sniffer.c`.
2. **Benchmark Python x C**: Ele usa o arquivo `results/benchmark.py` para injetar pacotes de teste simultaneamente contra a engine do scikit-learn e a engine nativa em C, gerando um comparativo de Throughput.
3. **Hardware End-to-End**: O código aciona nosso Sniffer C nativo e prova que o código consome apenas **~3MB de RAM** e tem latência irrisória (microssegundos).

---

## 🛰️ 2. O IoT-Shield Sniffer (Como Rodar no Roteador)

Junto com a matemática da IA, o projeto conta com um Sniffer ativo escrito em C Nativo. Ele intercepta o tráfego em tempo real no Kernel do roteador (usando `libpcap`), converte o fluxo IP/TCP/UDP em variáveis estatísticas e entrega direto para a sua IA.

### 📥 Binário Pré-Compilado (Releases)

Se você baixou o binário pronto diretamente da aba **Releases** do GitHub para a sua arquitetura, não é necessário compilar nada. Basta dar permissão de execução e rodar:

```bash
chmod +x iot_shield-Linux-x86_64

```

### ⚙️ Como Compilar Manualmente (Cross-Compilation)

**Atenção:** O comando `./scripts/run.sh --phase export` da etapa anterior **já compila o binário automaticamente** para a máquina onde o treinamento ocorreu!

Você só precisará recompilar manualmente caso vá transferir o firmware para um roteador com arquitetura diferente da sua máquina (ex: de um PC x86 para um roteador ARM ou MIPS).

Neste caso, envie os arquivos fonte (`iot_shield_model.c` e `iot_shield_sniffer.c`) para o roteador de destino (que deve conter o `gcc` e `libpcap-dev` instalados) e execute:

```bash
cd results/
gcc -O3 iot_shield_model.c iot_shield_sniffer.c -o iot_shield_sniffer -lpcap -lm
chmod +x iot_shield_sniffer
```

*Nota: Usamos a flag `-O3` para forçar o compilador a aplicar Otimização Máxima de CPU, garantindo a latência de microssegundos.*

### Modo 1: Análise Forense Offline (Arquivos PCAP)

Se você quer simular tráfego jogando um arquivo capturado contra a IA C:

```bash
./iot_shield_sniffer ../data/pcaps/Benign/dataset_benign.pcap

```

*O binário engolirá milhares de pacotes em poucos milissegundos e aplicará a detecção retroativamente.*

### Modo 2: Interceptação em Tempo Real no Roteador (Live)

Para colocar o escudo para funcionar na vida real e interceptar qualquer malware que passe pela placa de rede:

```bash
sudo ./iot_shield_sniffer eth0

```

*(Troque `eth0` por `wlan0`, `br-lan` ou a interface apropriada da sua rede).*

O binário rodará de forma limpa, não atrapalhando a banda ou a internet da casa. Quando um atacante tentar forçar acesso (Ex: Botnet Mirai escaneando portas SSH/Telnet), o painel emitirá instantaneamente no console:

```text
[!] ALERTA: Tráfego Malicioso Detectado! (Score: 99.80%) | 192.168.1.197:44321 -> 192.168.1.1:23 (Proto: 6)

```

---

## 🔒 Benefícios do Firmware Nativo (OpenWRT)

* **Memória Minimalista**: Como o código C foi arquitetado para possuir uma Tabela Hash estática de sessões, não ocorre memory-leak e nem intervenção do *Garbage Collector*, consumindo **menos de 4 Megabytes**.
* **Proteção Imediata**: A latência de repasse e leitura é tipicamente menor do que `5.0 µs`. O ataque é classificado antes mesmo do servidor IoT interno terminar de dar "Handshake" com o hacker.

---

## ⚠️ Aviso Arquitetural (Comptime Metaprogramming)

O firmware do **IoT-Shield** usa **Metaprogramação em Tempo de Compilação** para gerar um binário cirúrgico que economiza RAM e CPU de Roteadores:

* **Seleção Dinâmica**: O código C se **adapta sozinho** e exclui cálculos matemáticos se você habilitar ou desabilitar (no `excluded_features.txt`) qualquer uma das **45 variáveis padrão** estritamente mapeadas pelo buffer do projeto. O GCC aplicará *Dead Code Elimination (DCE)* no C automaticamente.
* **Criação de Novas Features**: No entanto, caso você (ou outro pesquisador) programe do zero uma **46ª Feature** (variável totalmente nova) dentro do `extractor.py`, o motor C não saberá como calculá-la nativamente a partir dos bytes brutos. Nesse caso, será obrigatório modificar o script Python de transpilação (`export_to_c.py`) e a estrutura estática do arquivo `iot_shield_sniffer.c` para ensinar ao compilador qual é a matemática C equivalente à nova feature Python.

## 🗄️ Bases de Dados (Datasets) Usadas no binário da aba releases

O IoT-Shield foi projetado para consumir tráfego de rede bruto (`.pcap`). Para reproduzir os testes acadêmicos ou treinar a sua própria IA, recomendamos as seguintes bases de dados de referência:

* **[SimNet](https://github.com/MagnoRamosDev/SimNet)**: Ferramenta determinística criada em conjunto com este projeto para gerar topologias de tráfego IoT e humano de forma controlada via contêineres.
* **[CIC-IDS-2017](https://www.unb.ca//cic/datasets/ids-2017.html)**: Base de dados da Universidade de New Brunswick, amplamente utilizada na literatura para extração de amostras de tráfego benigno de alta fidelidade.
* **[IoT-23](https://www.stratosphereips.org/datasets-iot23)**: Base de dados do Stratosphere Laboratory contendo capturas de rede reais de malwares IoT (como as botnets Mirai e Bashlite).

### 🧩 Como integrar essas bases no IoT-Shield?

A integração de qualquer base de dados externa no pipeline é extremamente simples e não requer alterações no código:

1. **Download:** Baixe os arquivos `.pcap` ou `.pcapng` das bases de dados acima.
2. **Armazenamento:** Coloque os arquivos baixados dentro do diretório `data/pcaps/`.
3. **Mapeamento (Rotulagem):** Abra o arquivo `data/datasets_list.txt` e adicione o caminho do arquivo seguido do **IP do Atacante**. Se o arquivo contiver apenas tráfego limpo (benigno), utilize o IP `0.0.0.0`.

**Exemplo de configuração no `datasets_list.txt`:**
```text
data/pcaps/CIC-IDS-2017/monday_benign.pcap 0.0.0.0
data/pcaps/IoT-23/mirai_capture.pcap 192.168.1.100
data/pcaps/SimNet/ataque_simulado.pcap 10.0.0.5
```

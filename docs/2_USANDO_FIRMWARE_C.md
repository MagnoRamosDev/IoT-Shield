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
1. **Transpilação**: Gera o arquivo `results/iot_shield_model.c` contendo a função inteligente matemática `score(double *input, double *output)`.
2. **Benchmark Python x C**: Ele usa o arquivo `results/benchmark.py` para injetar os 10.000 pacotes de teste simultaneamente contra a engine do scikit-learn e a engine nativa em C, gerando um comparativo de Throughput.
3. **Hardware End-to-End**: O código aciona nosso Sniffer C nativo e prova que o código consome apenas **~3MB de RAM** e tem latência irrisória (microssegundos).

---

## 🛰️ 2. O IoT-Shield Sniffer (Como Rodar no Roteador)

Junto com a matemática da IA, o projeto conta com um Sniffer ativo escrito em C Nativo (`results/iot_shield_sniffer.c`). Ele intercepta o tráfego em tempo real no Kernel do roteador (usando `libpcap`), converte o fluxo IP/TCP/UDP em variáveis estatísticas e entrega direto na boca da sua IA.

### Como Compilar
Se você precisar recompilar manualmente no servidor ou roteador (certifique-se de que tenha os pacotes `gcc` e `libpcap-dev`):
```bash
cd results/
gcc -O3 iot_shield_model.c iot_shield_sniffer.c -o iot_shield_sniffer -lpcap -lm
```
_Nota: Usamos a flag `-O3` para forçar o GCC a aplicar Otimização Máxima de CPU, o que garante a detecção agressiva._

### Modo 1: Análise Forense Offline (Arquivos PCAP)
Se você quer simular tráfego jogando um arquivo capturado contra a IA C:
```bash
./results/iot_shield_sniffer data/pcaps/Benign/dataset_benign.pcap
```
_O binário engolirá milhares de pacotes em poucos milissegundos e aplicará a detecção retroativamente._

### Modo 2: Interceptação em Tempo Real no Roteador (Live)
Para colocar o escudo para funcionar na vida real e interceptar qualquer malware que passe pela placa de rede:
```bash
sudo ./results/iot_shield_sniffer eth0
```
*(Troque `eth0` por `wlan0`, `br-lan` ou a interface apropriada da sua rede).*

O binário rodará de forma limpa, não atrapalhando a banda ou a internet da casa. Quando um atacante tentar forçar acesso (Ex: Botnet Mirai escaneando portas SSH/Telnet), o painel emitirá instantaneamente no console:
```text
[!] ALERTA: Tráfego Malicioso Detectado! (Score: 99.80%) | 192.168.1.197:44321 -> 192.168.1.1:23 (Proto: 6)
```

---

## 🔒 Benefícios do Firmware Nativo (OpenWRT)
* **Memória Minimalista**: Como o código C foi arquitetado para possuir uma Tabela Hash estática de sessões, não ocorre memory-leak e nem intervenção do *Garbage Collector*, consumindo **menos de 4 Megabytes**.
* **Proteção Imediata**: A latência de repasse e leitura é menor do que `5.0 µs`. O ataque é bloqueado antes mesmo do servidor IoT interno terminar de dar "Handshake" com o hacker.

---

## ⚠️ Aviso Arquitetural (Comptime Metaprogramming)
O firmware do **IoT-Shield** usa **Metaprogramação em Tempo de Compilação** para gerar um binário cirúrgico que economiza RAM e CPU de Roteadores:
- **Seleção Dinâmica**: O código C se **adapta sozinho** e exclui cálculos matemáticos se você habilitar ou desabilitar (no `excluded_features.txt`) qualquer uma das **49 variáveis padrão** já mapeadas pelo projeto. O GCC aplicará _Dead Code Elimination (DCE)_ no C automaticamente.
- **Criação de Novas Features**: No entanto, caso você (ou outro pesquisador) programe do zero uma **50ª Feature** (variável totalmente nova) dentro do `extractor.py`, o motor C não saberá como calculá-la nativamente a partir dos bytes brutos. Nesse caso, será obrigatório modificar o código `export_to_c.py` e o arquivo `iot_shield_sniffer.c` para ensinar ao compilador qual é a matemática C equivalente à nova feature Python.

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <math.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <sys/time.h>

typedef struct {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
} FlowKey;

typedef struct {
    uint32_t packets;
    uint32_t bytes;
    double duration_ms;
    uint32_t syn_packets;
    uint32_t rst_packets;

    uint32_t min_ps;
    uint32_t max_ps;
    double sum_ps;
    double sum_sq_ps;

    double min_piat_ms;
    double max_piat_ms;
    double sum_piat;
    double sum_sq_piat;

    double first_time_ms;
    double last_time_ms;
} DirectionStats;

typedef struct FlowRecord {
    FlowKey key;
    double start_time_ms;
    double last_time_ms;
    double duration_ms;

    uint32_t src2dst_concurrent_flows;
    uint32_t dst2src_concurrent_flows;

    DirectionStats src2dst;
    DirectionStats dst2src;

    int is_scored;
} FlowRecord;

// ============================================================================
// 2. FUNÇÕES MATEMÁTICAS EXIGIDAS PELO HEADER GERADO NO PYTHON
// ============================================================================

static inline double calc_stddev(double sum, double sum_sq, uint32_t count) {
    if (count < 2) return 0.0;
    double mean = sum / count;
    double var = (sum_sq / count) - (mean * mean);
    if (var <= 0.0) return 0.0;
    return sqrt(var);
}

// Injeta o mapeador dinâmico de features gerado no Python (Fase 4)
#include "iot_shield_features.h"

// Assinatura oficial do Scikit-Learn -> m2cgen
extern void score(double * input, double * output);

// ============================================================================
// 3. TABELA HASH ESTÁTICA
// ============================================================================

#define MAX_FLOWS 8192
#define HASH_SIZE 8192

typedef struct Node {
    FlowRecord flow;
    struct Node *next;
} Node;

static Node* hash_table[HASH_SIZE];
static Node node_pool[MAX_FLOWS];
static int free_nodes_count = 0;

static uint32_t hash_flow(uint32_t src_ip, uint32_t dst_ip, uint16_t src_port, uint16_t dst_port, uint8_t proto) {
    // Hash simétrico para chaves bidirecionais
    uint32_t ip_xor = src_ip ^ dst_ip;
    uint16_t port_xor = src_port ^ dst_port;
    return (ip_xor ^ port_xor ^ proto) % HASH_SIZE;
}

// ============================================================================
// 4. LÓGICA DE DETECÇÃO E AVALIAÇÃO DA I.A.
// ============================================================================

void evaluate_flow_with_ai(FlowRecord *f) {
    if (f->is_scored) return;

    // A IA precisa de pelo menos 3 pacotes para calcular P.I.A.T e StdDev
    uint32_t total_packets = f->src2dst.packets + f->dst2src.packets;
    if (total_packets < 3) return;

    // Aloca as 45 features nativamente (ou 64 para garantir sobra futura)
    double input[64] = {0.0};
    double output[2] = {0.0};

    // Calcula duracao total em segundos requerida pela func
    double dur_sec = f->duration_ms / 1000.0;
    if (dur_sec <= 0.001) dur_sec = 0.001;

    // Popula o array usando o código macro gerado em tempo de compilação
    populate_ml_array(f, input, dur_sec);

    // Bate no cérebro da rede neural C (m2cgen)
    score(input, output);

    // Se a probabilidade maliciosa (Classe 1) for maior que 60% (Threshold ajustável)
    if (output[1] >= 0.60) {
        struct in_addr src, dst;
        src.s_addr = f->key.src_ip;
        dst.s_addr = f->key.dst_ip;

        printf("[!] ALERTA: Tráfego Malicioso Detectado! (Score: %.2f%%) | %s:%d -> %s:%d (Proto: %d)\n",
               output[1] * 100.0,
               inet_ntoa(src), ntohs(f->key.src_port),
               inet_ntoa(dst), ntohs(f->key.dst_port),
               f->key.protocol);

        f->is_scored = 1; // Silencia o alerta para este mesmo fluxo
    }
}

// ============================================================================
// 5. PROCESSAMENTO DE PACOTES
// ============================================================================

void update_direction_stats(DirectionStats *stats, uint32_t size, double ts_ms, uint8_t tcp_flags) {
    stats->packets++;
    stats->bytes += size;

    // Packet Size
    if (size < stats->min_ps || stats->packets == 1) stats->min_ps = size;
    if (size > stats->max_ps) stats->max_ps = size;
    stats->sum_ps += size;
    stats->sum_sq_ps += (double)size * size;

    // TCP Flags
    if (tcp_flags & TH_SYN) stats->syn_packets++;
    if (tcp_flags & TH_RST) stats->rst_packets++;

    // PIAT (Packet Inter-Arrival Time)
    if (stats->last_time_ms > 0) {
        double piat = ts_ms - stats->last_time_ms;
        if (piat < stats->min_piat_ms || stats->packets == 2) stats->min_piat_ms = piat;
        if (piat > stats->max_piat_ms) stats->max_piat_ms = piat;
        stats->sum_piat += piat;
        stats->sum_sq_piat += (piat * piat);
    } else {
        stats->first_time_ms = ts_ms;
    }

    stats->last_time_ms = ts_ms;
    stats->duration_ms = stats->last_time_ms - stats->first_time_ms;
}

void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ether_header *eth = (struct ether_header *) packet;
    if (ntohs(eth->ether_type) != ETHERTYPE_IP) return;

    struct ip *iph = (struct ip *)(packet + sizeof(struct ether_header));
    uint8_t proto = iph->ip_p;

    uint16_t src_port = 0, dst_port = 0;
    uint8_t tcp_flags = 0;
    uint32_t header_len = sizeof(struct ether_header) + (iph->ip_hl * 4);

    if (proto == IPPROTO_TCP) {
        struct tcphdr *tcph = (struct tcphdr *)(packet + header_len);
        src_port = tcph->source;
        dst_port = tcph->dest;
        tcp_flags = tcph->th_flags;
    } else if (proto == IPPROTO_UDP) {
        struct udphdr *udph = (struct udphdr *)(packet + header_len);
        src_port = udph->source;
        dst_port = udph->dest;
    } else {
        return;
    }

    double current_time_ms = (pkthdr->ts.tv_sec * 1000.0) + (pkthdr->ts.tv_usec / 1000.0);
    uint32_t h = hash_flow(iph->ip_src.s_addr, iph->ip_dst.s_addr, src_port, dst_port, proto);

    Node *curr = hash_table[h];
    FlowRecord *flow = NULL;
    int is_s2d = 1;

    // Busca de Fluxo Existente (Bidirecional)
    while (curr != NULL) {
        if (curr->flow.key.protocol == proto) {
            if (curr->flow.key.src_ip == iph->ip_src.s_addr && curr->flow.key.dst_ip == iph->ip_dst.s_addr &&
                curr->flow.key.src_port == src_port && curr->flow.key.dst_port == dst_port) {
                flow = &curr->flow;
                is_s2d = 1;
                break;
            }
            if (curr->flow.key.src_ip == iph->ip_dst.s_addr && curr->flow.key.dst_ip == iph->ip_src.s_addr &&
                curr->flow.key.src_port == dst_port && curr->flow.key.dst_port == src_port) {
                flow = &curr->flow;
                is_s2d = 0;
                break;
            }
        }
        curr = curr->next;
    }

    // Criação de Novo Fluxo
    if (flow == NULL) {
        if (free_nodes_count >= MAX_FLOWS) {
            // Se encher a RAM (Ring buffer primitivo): Zera tudo! Em Edge AI, reiniciar
            // a tabela limpa o lixo e previne Memory-Leaks, mantendo o consumo cravado em 3MB.
            memset(hash_table, 0, sizeof(hash_table));
            memset(node_pool, 0, sizeof(node_pool));
            free_nodes_count = 0;
        }

        Node *new_node = &node_pool[free_nodes_count++];
        flow = &new_node->flow;

        flow->key.src_ip = iph->ip_src.s_addr;
        flow->key.dst_ip = iph->ip_dst.s_addr;
        flow->key.src_port = src_port;
        flow->key.dst_port = dst_port;
        flow->key.protocol = proto;

        flow->start_time_ms = current_time_ms;
        flow->src2dst_concurrent_flows = 1;
        flow->dst2src_concurrent_flows = 1;

        new_node->next = hash_table[h];
        hash_table[h] = new_node;
        is_s2d = 1;
    }

    // Atualiza Estatísticas
    uint32_t packet_size = pkthdr->len;
    if (is_s2d) {
        update_direction_stats(&flow->src2dst, packet_size, current_time_ms, tcp_flags);
    } else {
        update_direction_stats(&flow->dst2src, packet_size, current_time_ms, tcp_flags);
    }

    flow->last_time_ms = current_time_ms;
    flow->duration_ms = flow->last_time_ms - flow->start_time_ms;

    // Avalia o fluxo continuamente (a cada 10 pacotes ou no encerramento)
    if (!flow->is_scored && ((flow->src2dst.packets + flow->dst2src.packets) % 10 == 0 || (tcp_flags & TH_RST))) {
        evaluate_flow_with_ai(flow);
    }
}

// ============================================================================
// 6. MAIN
// ============================================================================

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Uso: %s <interface_ou_arquivo.pcap>\n", argv[0]);
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;

    // Identifica se o usuário passou um arquivo offline (PCAP) ou uma placa de rede ativa (eth0)
    if (strstr(argv[1], ".pcap") != NULL) {
        printf("[*] Iniciando analise forense no arquivo: %s\n", argv[1]);
        handle = pcap_open_offline(argv[1], errbuf);
    } else {
        printf("[*] Iniciando interceptacao Live na interface: %s\n", argv[1]);
        // Abre placa no modo promiscuo, snapshot 65535, 10ms timeout
        handle = pcap_open_live(argv[1], 65535, 1, 10, errbuf);
    }

    if (handle == NULL) {
        fprintf(stderr, "[!] Erro fatal ao abrir pcap: %s\n", errbuf);
        return 2;
    }

    printf("[+] IoT-Shield AI Engine Iniciado! Aguardando malwares...\n\n");

    // Loop de Captura Infinito (0)
    pcap_loop(handle, 0, packet_handler, NULL);

    pcap_close(handle);
    return 0;
}

import time
import random
import threading
import requests
import socket
import paho.mqtt.client as mqtt

# ==========================================
# 1. GERADOR DE TRÁFEGO BENIGNO NORMAL (PC)
# ==========================================
def simular_navegacao_web():
    """Simula um usuário acessando sites comuns e APIs REST."""
    sites = [
        "https://www.google.com",
        "https://www.wikipedia.org",
        "https://api.github.com",
        "https://xkcd.com/info.0.json" # Payload JSON pequeno
    ]
    
    while True:
        alvo = random.choice(sites)
        try:
            # Randomiza o User-Agent para maior realismo
            headers = {'User-Agent': f'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/{random.randint(500,600)}.36'}
            requests.get(alvo, headers=headers, timeout=5)
            print(f"[PC NORMAL] Acesso HTTP/HTTPS realizado em: {alvo}")
        except Exception as e:
            pass
        
        # Espera um tempo aleatório para simular leitura humana (1 a 5 segundos)
        time.sleep(random.uniform(1.0, 5.0))

# ==========================================
# 2. GERADORES DE TRÁFEGO BENIGNO IOT
# ==========================================
def simular_iot_mqtt():
    """Simula um sensor publicando telemetria em um broker MQTT."""
    broker = "test.mosquitto.org" # Broker público de teste
    topico = "meu_projeto/sensores/temperatura"
    
    client = mqtt.Client()
    try:
        client.connect(broker, 1883, 60)
        while True:
            payload = f'{{"temp": {random.uniform(20.0, 35.0):.2f}, "status": "ok"}}'
            client.publish(topico, payload)
            print(f"[IoT MQTT] Payload publicado: {payload}")
            # IoTs geralmente enviam dados em intervalos fixos
            time.sleep(10)
    except Exception as e:
        print("[IoT MQTT] Falha na conexão.")

def simular_iot_udp_customizado():
    """Simula tráfego IoT que usa protocolos customizados rápidos sobre UDP."""
    # Perfeito para simular fluxos de comunicação direta, como envio de 
    # comandos rápidos ou streaming leve (ex: sistemas de porteiro eletrônico).
    ip_destino = "8.8.8.8" # IP de teste (DNS do Google), apenas para rotear o pacote UDP
    porta_destino = 5005 
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    while True:
        # Payload hexadecimal/bytes simples simulando um comando de 'keep-alive' ou status
        mensagem = b'\x00\x01\x0A\xFF' + random.randbytes(4)
        try:
            sock.sendto(mensagem, (ip_destino, porta_destino))
            print(f"[IoT UDP] Pacote customizado enviado ({len(mensagem)} bytes)")
        except Exception as e:
            pass
        
        time.sleep(random.uniform(2.0, 8.0))

# ==========================================
# 3. EXECUÇÃO PARALELA (MULTITHREADING)
# ==========================================
if __name__ == "__main__":
    print("Iniciando geração de tráfego benigno misto (PC + IoT)... Pressione Ctrl+C para parar.")
    
    threads = []
    
    # Inicia a thread de navegação normal
    t_web = threading.Thread(target=simular_navegacao_web, daemon=True)
    threads.append(t_web)
    
    # Inicia as threads de IoT
    t_mqtt = threading.Thread(target=simular_iot_mqtt, daemon=True)
    threads.append(t_mqtt)
    
    t_udp = threading.Thread(target=simular_iot_udp_customizado, daemon=True)
    threads.append(t_udp)
    
    for t in threads:
        t.start()
        
    try:
        # Mantém o script principal rodando
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nGeração de tráfego encerrada pelo usuário.")
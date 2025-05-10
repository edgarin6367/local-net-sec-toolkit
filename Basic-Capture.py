from scapy.all import sniff, IP

def mostrar_paquete(paquete):
    if IP in paquete:
        ip_origen = paquete[IP].src
        ip_destino = paquete[IP].dst
        protocolo = paquete[IP].proto  # 6 para TCP, 17 para UDP, 1 para ICMP, etc.
        print(f"Paquete IP: Origen -> Destino = {ip_origen} -> {ip_destino} | Protocolo = {protocolo}")

def iniciar_captura():
    print("Iniciando captura de tráfico...")
    sniff(prn=mostrar_paquete, store=0)

if __name__ == "__main__":
    iniciar_captura()
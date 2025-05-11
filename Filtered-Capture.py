from scapy.all import sniff, IP
import sys
from collections import defaultdict

paquetes_por_destino = defaultdict(int)
contador_paquetes = 0
limite_conteo = 100 

def mostrar_paquete(paquete):
    global paquetes_por_destino, contador_paquetes, limite_conteo
    if IP in paquete:
        ip_origen = paquete[IP].src
        ip_destino = paquete[IP].dst
        protocolo = paquete[IP].proto
        protocolo_nombre = "Desconocido"
        if protocolo == 6:
            protocolo_nombre = "TCP"
        elif protocolo == 17:
            protocolo_nombre = "UDP"
        elif protocolo == 1:
            protocolo_nombre = "ICMP"
        print(f"IP ({protocolo_nombre}) | {ip_origen} -> {ip_destino}")
        paquetes_por_destino[ip_destino] += 1
        contador_paquetes += 1

        if contador_paquetes >= limite_conteo:
            print("\n--- Conteo de Paquetes por Destino (últimos {} paquetes) ---".format(limite_conteo))
            for destino, count in sorted(paquetes_por_destino.items(), key=lambda item: item[1], reverse=True):
                print(f"Destino: {destino}, Conteo: {count}")
            paquetes_por_destino.clear()
            contador_paquetes = 0
            

def iniciar_captura(protocolo_filtro=None):
    print(f"Iniciando captura de tráfico {'filtrado por ' + protocolo_filtro if protocolo_filtro else 'sin filtro'}...")
    if protocolo_filtro:
        sniff(prn=mostrar_paquete, store=0, filter=protocolo_filtro)
    else:
        sniff(prn=mostrar_paquete, store=0)

if __name__ == "__main__":
    protocolo = None
    if len(sys.argv) > 1:
        protocolo = sys.argv[1].lower()
        print(f"Filtrando por protocolo: {protocolo.upper()}")
    iniciar_captura(protocolo)
from scapy.all import sniff, IP, TCP
import sys
from collections import defaultdict
import time

# Umbral: número de puertos distintos a los que un host debe intentar conectar en un tiempo dado para considerarse un escaneo
UMBRAL_PUERTOS = 5
VENTANA_TIEMPO = 5  # segundos

# Estructura para almacenar los intentos de conexión SYN recientes
conexiones_syn = defaultdict(lambda: defaultdict(list))  # origen -> destino -> [timestamps de SYN]

def mostrar_paquete(paquete):
    global conexiones_syn
    if IP in paquete and TCP in paquete:
        ip_origen = paquete[IP].src
        ip_destino = paquete[IP].dst
        puerto_destino = paquete[TCP].dport
        flags = paquete[TCP].flags

        protocolo_nombre = "TCP"
        if paquete[IP].proto == 17:
            protocolo_nombre = "UDP"
        elif paquete[IP].proto == 1:
            protocolo_nombre = "ICMP"

        print(f"Paquete IP ({protocolo_nombre}): Origen={ip_origen}:{paquete[TCP].sport if TCP in paquete else ''}, Destino={ip_destino}:{puerto_destino if TCP in paquete else ''}, Flags={flags if TCP in paquete else ''}")

        # Detección básica de escaneo de puertos TCP
        if flags == 'S':  # SYN flag activado (intento de nueva conexión)
            timestamp = time.time()
            conexiones_syn[ip_origen][ip_destino].append((puerto_destino, timestamp))
            verificar_escaneo(ip_origen, ip_destino)

def verificar_escaneo(ip_origen, ip_destino):
    global conexiones_syn, UMBRAL_PUERTOS, VENTANA_TIEMPO
    ahora = time.time()
    intentos_recientes = []
    if ip_destino in conexiones_syn[ip_origen]:
        # Filtramos los intentos que están dentro de la ventana de tiempo
        conexiones_syn[ip_origen][ip_destino] = [(puerto, ts) for puerto, ts in conexiones_syn[ip_origen][ip_destino] if ahora - ts < VENTANA_TIEMPO]
        puertos_intentados = {puerto for puerto, ts in conexiones_syn[ip_origen][ip_destino]}
        if len(puertos_intentados) >= UMBRAL_PUERTOS:
            print(f"\n*** Posible escaneo de puertos detectado ***")
            print(f"Origen: {ip_origen} está intentando conectar a múltiples puertos ({len(puertos_intentados)}) en Destino: {ip_destino} en un corto período.")
            # Opcional: podríamos limpiar los registros de este origen/destino para evitar alertas repetidas inmediatamente
            # del conexiones_syn[ip_origen][ip_destino]

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
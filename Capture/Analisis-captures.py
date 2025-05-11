from scapy.all import sniff, IP, TCP
import sys
from collections import defaultdict
import time
import geoip2.database

# --- Configuraciones ---
UMBRAL_PUERTOS = 5
VENTANA_TIEMPO_ESCANEO = 5
BASE_DE_DATOS_GEOIP = 'GeoLite2-City.mmdb'

# --- Umbrales para Detección de DoS ---
UMBRAL_PAQUETES_DOS = 100
VENTANA_TIEMPO_DOS = 10
trafico_reciente = defaultdict(lambda: defaultdict(lambda: []))

# --- Variables Globales ---
conexiones_syn = defaultdict(lambda: defaultdict(list))
posibles_xmas = defaultdict(lambda: defaultdict(int))  # destino -> origen -> conteo

try:
    lector_geoip = geoip2.database.Reader(BASE_DE_DATOS_GEOIP)
except FileNotFoundError:
    lector_geoip = None
    print(f"Advertencia: No se encontró la base de datos GeoIP en '{BASE_DE_DATOS_GEOIP}'. La funcionalidad de GeoIP Lookup no estará disponible.")

def obtener_ubicacion(ip_address):
    try:
        if lector_geoip:
            respuesta = lector_geoip.city(ip_address)
            ciudad = respuesta.city.name if respuesta.city.name else "Desconocida"
            pais = respuesta.country.name if respuesta.country.name else "Desconocido"
            return f"{ciudad}, {pais}"
        else:
            return "No disponible (base de datos no cargada)"
    except geoip2.errors.AddressNotFoundError:
        return "Ubicación no encontrada"
    except Exception as e:
        return f"Error al obtener ubicación: {e}"

def detectar_dos(ip_origen, ip_destino):
    global trafico_reciente, UMBRAL_PAQUETES_DOS, VENTANA_TIEMPO_DOS
    ahora = time.time()
    trafico_reciente[ip_origen][ip_destino] = [ts for ts in trafico_reciente[ip_origen][ip_destino] if ahora - ts < VENTANA_TIEMPO_DOS]
    trafico_reciente[ip_origen][ip_destino].append(ahora)
    if len(trafico_reciente[ip_origen][ip_destino]) > UMBRAL_PAQUETES_DOS:
        ubicacion_origen = obtener_ubicacion(ip_origen)
        ubicacion_destino = obtener_ubicacion(ip_destino)
        print(f"\n*** Posible ataque DDoS detectado ***")
        print(f"Origen: {ip_origen} ({ubicacion_origen}) está enviando un gran número de paquetes ({len(trafico_reciente[ip_origen][ip_destino])} en {VENTANA_TIEMPO_DOS} segundos) a Destino: {ip_destino} ({ubicacion_destino}).")

def mostrar_paquete(paquete):
    global conexiones_syn, posibles_xmas
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

        ubicacion_destino = obtener_ubicacion(ip_destino)
        print(f"Paquete IP ({protocolo_nombre}): Origen={ip_origen}, Destino={ip_destino} ({ubicacion_destino})")
        detectar_dos(ip_origen, ip_destino)

        if TCP in paquete:
            if paquete[TCP].flags == 'S':
                timestamp = time.time()
                conexiones_syn[ip_origen][ip_destino].append((paquete[TCP].dport, timestamp))
                verificar_escaneo(ip_origen, ip_destino)
            elif paquete[TCP].flags == 'FPU':  # FIN, PSH, URG activadas
                posibles_xmas[ip_destino][ip_origen] += 1
                print(f"\n*** Posible Xmas Scan detectado ***")
                print(f"Paquete Xmas (FIN+PSH+URG) desde Origen: {ip_origen} hacia Destino: {ip_destino} ({ubicacion_destino}).")

def verificar_escaneo(ip_origen, ip_destino):
    global conexiones_syn, UMBRAL_PUERTOS, VENTANA_TIEMPO_ESCANEO
    ahora = time.time()
    if ip_destino in conexiones_syn[ip_origen]:
        conexiones_syn[ip_origen][ip_destino] = [(puerto, ts) for puerto, ts in conexiones_syn[ip_origen][ip_destino] if ahora - ts < VENTANA_TIEMPO_ESCANEO]
        puertos_intentados = {puerto for puerto, ts in conexiones_syn[ip_origen][ip_destino]}
        if len(puertos_intentados) >= UMBRAL_PUERTOS:
            ubicacion_destino = obtener_ubicacion(ip_destino)
            print(f"\n*** Posible escaneo de puertos (SYN) detectado ***")
            print(f"Origen: {ip_origen} está intentando conectar a múltiples puertos ({len(puertos_intentados)}) en Destino: {ip_destino} ({ubicacion_destino}) en un corto período.")

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
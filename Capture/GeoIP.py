from scapy.all import sniff, IP, TCP
import sys
from collections import defaultdict
import time
import geoip2.database

# --- Configuraciones ---
UMBRAL_PUERTOS = 5
VENTANA_TIEMPO = 5
BASE_DE_DATOS_GEOIP = 'GeoLite2-City.mmdb'  # Ajusta la ruta si es necesario

# --- Variables Globales ---
conexiones_syn = defaultdict(lambda: defaultdict(list))

try:
    lector_geoip = geoip2.database.Reader(BASE_DE_DATOS_GEOIP)
except FileNotFoundError:
    lector_geoip = None
    print(f"Advertencia: No se encontró la base de datos GeoIP en '{BASE_DE_DATOS_GEOIP}'. La funcionalidad de GeoIP Lookup no estará disponible.")

def obtener_ubicacion(ip_address):
    try:
        if lector_geoip:
            respuesta = lector_geoip.city(ip_address)
            ciudad = respuesta.city.name if respuesta.city.name else "Unknown"
            pais = respuesta.country.name if respuesta.country.name else "Unkown"
            return f"{ciudad}, {pais}"
        else:
            return "No disponible (base de datos no cargada)"
    except geoip2.errors.AddressNotFoundError:
        return "Ubicación no encontrada"
    except Exception as e:
        return f"Error al obtener ubicación: {e}"

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

        ubicacion_destino = obtener_ubicacion(ip_destino)
        print(f"IP ({protocolo_nombre}): {ip_origen}:{paquete[TCP].sport if TCP in paquete else ''} -> {ip_destino}:{puerto_destino if TCP in paquete else ''} ({ubicacion_destino}), Flags={flags if TCP in paquete else ''}")

        if flags == 'S':
            timestamp = time.time()
            conexiones_syn[ip_origen][ip_destino].append((puerto_destino, timestamp))
            verificar_escaneo(ip_origen, ip_destino)

def verificar_escaneo(ip_origen, ip_destino):
    global conexiones_syn, UMBRAL_PUERTOS, VENTANA_TIEMPO
    ahora = time.time()
    if ip_destino in conexiones_syn[ip_origen]:
        conexiones_syn[ip_origen][ip_destino] = [(puerto, ts) for puerto, ts in conexiones_syn[ip_origen][ip_destino] if ahora - ts < VENTANA_TIEMPO]
        puertos_intentados = {puerto for puerto, ts in conexiones_syn[ip_origen][ip_destino]}
        if len(puertos_intentados) >= UMBRAL_PUERTOS:
            ubicacion_destino = obtener_ubicacion(ip_destino)
            print(f"\n*** Posible escaneo de puertos detectado ***")
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
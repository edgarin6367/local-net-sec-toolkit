from scapy.all import sniff, IP, TCP
import sys
from collections import defaultdict
import time
import geoip2.database
import logging
import argparse
from colorama import Fore, Style, init

# Inicializa colorama
init(autoreset=True)

# --- Configuraciones ---
UMBRAL_PUERTOS = 5
VENTANA_TIEMPO_ESCANEO = 5
BASE_DE_DATOS_GEOIP = 'GeoLite2-City.mmdb'
LOG_FILE = 'network_monitor.log'
RANGOS_LOCALES = ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']

# --- Umbrales para Detección de DoS ---
UMBRAL_PAQUETES_DOS = 100
VENTANA_TIEMPO_DOS = 10
trafico_reciente = defaultdict(lambda: defaultdict(lambda: []))

# --- Variables Globales ---
conexiones_syn = defaultdict(lambda: defaultdict(list))
posibles_xmas = defaultdict(lambda: defaultdict(int))

# --- Configuración del Logging ---
logging.basicConfig(filename=LOG_FILE, level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

try:
    lector_geoip = geoip2.database.Reader(BASE_DE_DATOS_GEOIP)
except FileNotFoundError:
    lector_geoip = None
    logging.warning(f"No se encontró la base de datos GeoIP en '{BASE_DE_DATOS_GEOIP}'. La funcionalidad de GeoIP Lookup no estará disponible.")

def obtener_ubicacion(ip_address):
    try:
        if lector_geoip:
            respuesta = lector_geoip.city(ip_address)
            ciudad = respuesta.city.name if respuesta.city.name else "Desconocida"
            pais = respuesta.country.name if respuesta.country.name else "Desconocido"
            return f"{ciudad}, {pais}"
        else:
            return "No disponible"
    except geoip2.errors.AddressNotFoundError:
        return "Ubicación no encontrada"
    except Exception as e:
        return f"Error al obtener ubicación: {e}"

def es_local(ip_address):
    from ipaddress import ip_address as ip_obj, ip_network
    try:
        ip = ip_obj(ip_address)
        for rango in RANGOS_LOCALES:
            if ip in ip_network(rango, strict=False):
                return True
    except ValueError:
        return False
    return False

def detectar_dos(ip_origen, ip_destino, ignorar_local):
    global trafico_reciente, UMBRAL_PAQUETES_DOS, VENTANA_TIEMPO_DOS
    if ignorar_local and (es_local(ip_origen) or es_local(ip_destino)):
        return
    ahora = time.time()
    trafico_reciente[ip_origen][ip_destino] = [ts for ts in trafico_reciente[ip_origen][ip_destino] if ahora - ts < VENTANA_TIEMPO_DOS]
    trafico_reciente[ip_origen][ip_destino].append(ahora)
    if len(trafico_reciente[ip_origen][ip_destino]) > UMBRAL_PAQUETES_DOS:
        ubicacion_origen = obtener_ubicacion(ip_origen)
        ubicacion_destino = obtener_ubicacion(ip_destino)
        mensaje = f"{Fore.RED}*** Posible ataque DDoS detectado ***{Style.RESET_ALL}\n" \
                  f"Origen: {Fore.WHITE}{ip_origen}{Style.RESET_ALL} ({ubicacion_origen}) está enviando un gran número de paquetes " \
                  f"({Fore.RED}{len(trafico_reciente[ip_origen][ip_destino])}{Style.RESET_ALL} en {VENTANA_TIEMPO_DOS} segundos) a " \
                  f"Destino: {Fore.WHITE}{ip_destino}{Style.RESET_ALL} ({ubicacion_destino})."
        print(mensaje)
        logging.warning(f"Posible ataque DDoS detectado. Origen: {ip_origen} ({ubicacion_origen}) está enviando un gran número de paquetes ({len(trafico_reciente[ip_origen][ip_destino])} en {VENTANA_TIEMPO_DOS} segundos) a Destino: {ip_destino} ({ubicacion_destino}).")

def mostrar_paquete(paquete, ignorar_local):
    global conexiones_syn, posibles_xmas
    if IP in paquete:
        ip_origen = paquete[IP].src
        ip_destino = paquete[IP].dst

        if ignorar_local and (es_local(ip_origen) or es_local(ip_destino)):
            return

        protocolo = paquete[IP].proto
        protocolo_nombre = "Desconocido"
        if protocolo == 6:
            protocolo_nombre = "TCP"
        elif protocolo == 17:
            protocolo_nombre = "UDP"
        elif protocolo == 1:
            protocolo_nombre = "ICMP"

        ubicacion_destino = obtener_ubicacion(ip_destino)
        print(f"Paquete IP ({protocolo_nombre}): Origen={Fore.WHITE}{ip_origen}{Style.RESET_ALL}, Destino={Fore.WHITE}{ip_destino}{Style.RESET_ALL} ({ubicacion_destino})")
        detectar_dos(ip_origen, ip_destino, ignorar_local)

        if TCP in paquete:
            if paquete[TCP].flags == 'S':
                timestamp = time.time()
                conexiones_syn[ip_origen][ip_destino].append((paquete[TCP].dport, timestamp))
                verificar_escaneo(ip_origen, ip_destino, ignorar_local)
            elif paquete[TCP].flags == 'FPU':
                ubicacion_destino = obtener_ubicacion(ip_destino)
                mensaje = f"{Fore.RED}*** Posible Xmas Scan detectado ***{Style.RESET_ALL}\n" \
                          f"Paquete Xmas (FIN+PSH+URG) desde Origen: {Fore.WHITE}{ip_origen}{Style.RESET_ALL} hacia Destino: {Fore.WHITE}{ip_destino}{Style.RESET_ALL} ({ubicacion_destino})."
                print(mensaje)
                logging.warning(f"Posible Xmas Scan detectado. Paquete Xmas (FIN+PSH+URG) desde Origen: {ip_origen} hacia Destino: {ip_destino} ({ubicacion_destino}).")

def verificar_escaneo(ip_origen, ip_destino, ignorar_local):
    global conexiones_syn, UMBRAL_PUERTOS, VENTANA_TIEMPO_ESCANEO
    if ignorar_local and (es_local(ip_origen) or es_local(ip_destino)):
        return
    ahora = time.time()
    if ip_destino in conexiones_syn[ip_origen]:
        conexiones_syn[ip_origen][ip_destino] = [(puerto, ts) for puerto, ts in conexiones_syn[ip_origen][ip_destino] if ahora - ts < VENTANA_TIEMPO_ESCANEO]
        puertos_intentados = {puerto for puerto, ts in conexiones_syn[ip_origen][ip_destino]}
        if len(puertos_intentados) >= UMBRAL_PUERTOS:
            ubicacion_destino = obtener_ubicacion(ip_destino)
            mensaje = f"{Fore.RED}*** Posible escaneo de puertos (SYN) detectado ***{Style.RESET_ALL}\n" \
                      f"Origen: {Fore.WHITE}{ip_origen}{Style.RESET_ALL} está intentando conectar a múltiples puertos ({Fore.RED}{len(puertos_intentados)}{Style.RESET_ALL}) " \
                      f"en Destino: {Fore.WHITE}{ip_destino}{Style.RESET_ALL} ({ubicacion_destino}) en un corto período."
            print(mensaje)
            logging.warning(f"Posible escaneo de puertos (SYN) detectado. Origen: {ip_origen} está intentando conectar a múltiples puertos ({len(puertos_intentados)}) en Destino: {ip_destino} ({ubicacion_destino}) en un corto período.")

def iniciar_captura(protocolo_filtro=None, ignorar_local=False):
    print(f"Iniciando captura de tráfico {'filtrado por ' + protocolo_filtro if protocolo_filtro else 'sin filtro'} {'(ignorando tráfico local)' if ignorar_local else ''}...")
    sniff(prn=lambda x: mostrar_paquete(x, ignorar_local), store=0, filter=protocolo_filtro)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Monitor de red con detección de anomalías. "
                                                 "Captura tráfico de red, filtra por protocolo y detecta posibles escaneos de puertos, ataques DoS y Xmas Scans.")
    parser.add_argument("-p", "--protocolo", help="Filtrar el tráfico capturado por un protocolo específico (tcp, udp, icmp, etc.).")
    parser.add_argument("-il", "--ignorar_local", action="store_true",
                        help="Ignorar el tráfico que se origine o destine a direcciones IP dentro de rangos de redes locales privadas.")
    args = parser.parse_args()

    iniciar_captura(args.protocolo, args.ignorar_local)
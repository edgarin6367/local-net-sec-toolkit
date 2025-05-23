# home-network-security-lab

Este es un proyecto personal para explorar y mejorar la seguridad de mi red doméstica mediante el análisis de tráfico y pruebas de penetración éticas. El objetivo es aprender sobre seguridad de redes y demostrar habilidades en un portafolio de ciberseguridad.

## Funcionalidades Actuales

* **Captura de Tráfico de Red:** Captura paquetes de red en tiempo real.
* **Filtrado por Protocolo:** Permite filtrar la captura de tráfico por protocolos específicos (TCP, UDP, ICMP, etc.) utilizando el argumento `-p` o `--protocolo`.
* **Detección Básica de Escaneo de Puertos (SYN Scan):** Alerta si una dirección IP de origen intenta conectar a múltiples puertos de destino en un corto período.
* **Detección Básica de Ataque DoS:** Alerta si se detecta un volumen inusualmente alto de tráfico desde una única fuente hacia un único destino en un corto período.
* **Detección de Xmas Scans:** Alerta al detectar paquetes TCP con las flags FIN, PSH y URG activadas.
* **GeoIP Lookup (Opcional):** Muestra la ubicación geográfica (ciudad y país) de las direcciones IP de destino utilizando la base de datos GeoLite2 City.
* **Logging a Archivo:** Las alertas de seguridad se registran en el archivo `network_monitor.log`.
* **Exclusión de Tráfico Local (Opcional):** Permite ignorar el tráfico dentro de redes locales privadas utilizando el argumento `-il` o `--ignorar_local`.
* **Ayuda en Línea:** Muestra información sobre cómo usar el script con las opciones `-h` o `--help`.
* **Salida con Colores:** Utiliza colores en la consola para facilitar la identificación de la información y las alertas.

## Requisitos de Instalación

Antes de ejecutar este script, asegúrate de tener instalados los siguientes componentes:

1.  **Python 3:** El script está escrito en Python 3. Puedes descargarlo desde [https://www.python.org/downloads/](https://www.python.org/downloads/).

2.  **Scapy:** La librería de Python para la manipulación de paquetes. Puedes instalarla usando pip:
    ```bash
    pip install scapy
    ```
    En algunos sistemas, podrías necesitar permisos de administrador:
    ```bash
    sudo pip install scapy
    ```

3.  **geoip2:** La librería de Python para realizar búsquedas de ubicación geográfica por IP. Puedes instalarla usando pip:
    ```bash
    pip install geoip2
    ```

4.  **Base de Datos GeoLite2 City:** Necesitarás descargar la base de datos "GeoLite2 City" de MaxMind. **Es necesario registrarse para obtener una clave de licencia gratuita para descargarla.** Guarda el archivo `.mmdb` (por ejemplo, `GeoLite2-City.mmdb`) en el mismo directorio que el script o en una subcarpeta llamada `data`.

5.  **colorama:** La librería de Python para añadir color al texto en la consola. Puedes instalarla usando pip:
    ```bash
    pip install colorama
    ```

## Cómo Ejecutar

1.  Clona este repositorio a tu máquina local.
2.  Navega al directorio del proyecto.
3.  Ejecuta el script con permisos de administrador (o `sudo` en Linux/macOS) para poder capturar tráfico de red:

    ```bash
    sudo python Alerts_and_Logging.py
    ```

    **Opciones:**

    * **Filtrar por protocolo:**
        ```bash
        sudo python Alerts_and_Logging.py -p tcp
        sudo python Alerts_and_Logging.py --protocolo udp
        ```

    * **Ignorar tráfico local:**
        ```bash
        sudo python Alerts_and_Logging -il
        sudo python Alerts_and_Logging --ignorar_local
        ```

    * **Combinar opciones:**
        ```bash
        sudo python Alerts_and_Logging.py -p tcp -il
        ```

    * **Mostrar ayuda:**
        ```bash
        python Alerts_and_Logging -h
        python Alerts_and_Logging --help
        ```

## Próximas Mejoras (Roadmap)

* [ ] Detección de fragmentación IP maliciosa.
* [ ] Análisis de flags TCP avanzado (detección de FIN/NULL/Xmas Scans más robusta).
* [ ] Alertas más sofisticadas (por ejemplo, por umbral de eventos).
* [ ] Posibilidad de especificar la interfaz de red a escuchar.
* [ ] ... ¡tus ideas son bienvenidas!

## Contribuciones

¡Las contribuciones son bienvenidas! Si tienes ideas para mejorar este proyecto, no dudes en crear un pull request.

## Licencia

[Añade aquí la licencia que desees utilizar, por ejemplo, MIT License]
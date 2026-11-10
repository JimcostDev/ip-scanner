# IP Scanner

Herramienta ligera y autónoma en Go para diagnosticar redes locales en Windows. Descubre qué direcciones IP están ocupadas y cuáles están libres para configurar dispositivos de red sin provocar conflictos de IP.

---

## ¿Qué hace?

- **Detecta la red local:** Identifica la interfaz activa, la dirección IPv4, la máscara y calcula el rango de la subred automáticamente.
- **Escaneo activo por ARP:** Envía peticiones ARP a nivel de capa de enlace (L2). Detecta dispositivos activos incluso si tienen el firewall activado o bloquean ping (ICMP).
- **Identificación de dispositivos:** Muestra la dirección IP, MAC, fabricante (OUI) y nombre del equipo (NetBIOS / DNS) cuando está disponible.
- **Recomendación de IPs libres:** Sugiere direcciones disponibles para asignaciones estáticas fuera del rango DHCP.
- **Pausa automática al finalizar:** La ventana de consola permanece abierta tras terminar el análisis (o ante errores) para que puedas leer los resultados con calma antes de pulsar ENTER.

---

## Cómo ejecutar

### Opción 1: Con Go directamente (Entorno de desarrollo)
Si tienes Go instalado, puedes ejecutarlo directamente desde la raíz del proyecto sin compilar:

```cmd
go run .
```

También puedes pasarle cualquier parámetro:
```cmd
go run . -only-free
go run . -list-ifaces
```

### Opción 2: Doble clic en el ejecutable (Recomendada para técnicos)
Haz doble clic sobre `ip-scanner.exe`. El programa abrirá la consola, escaneará la red automáticamente y esperará a que pulses ENTER para cerrarse.

### Opción 3: Desde terminal (PowerShell o CMD)
Abre la consola en la carpeta del ejecutable:

```cmd
ip-scanner.exe
```

### Opciones y parámetros útiles:

```cmd
# Ver las interfaces de red disponibles
ip-scanner.exe -list-ifaces

# Seleccionar una interfaz específica
ip-scanner.exe -i "Ethernet"

# Mostrar solo las direcciones libres
ip-scanner.exe -only-free

# Mostrar solo las direcciones ocupadas
ip-scanner.exe -only-occupied

# Escaneo más rápido sin resolución de nombres
ip-scanner.exe -no-names

# Ajustar concurrencia (por defecto 40)
ip-scanner.exe -w 50

# Desactivar la pausa al terminar (ideal para scripts automáticos)
ip-scanner.exe -no-pause
```

---

## Cómo compilar

Si deseas generar el ejecutable desde el código fuente (requiere Go 1.27 o superior):

```cmd
go build -trimpath -ldflags="-s -w" -o ip-scanner.exe .
```

El archivo resultante `ip-scanner.exe` es 100% autónomo y no requiere tener Go ni dependencias adicionales instaladas.

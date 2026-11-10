package scanner

import (
	"bytes"
	"net"
	"strings"
	"time"
)

// ResolveHostname intenta obtener el nombre del host mediante NetBIOS (UDP 137) y Reverse DNS.
// Solo debe invocarse sobre IPs ya confirmadas como OCUPADAS para evitar demoras innecesarias.
func ResolveHostname(ip net.IP, timeout time.Duration) string {
	ipStr := ip.String()

	// 1. Intentar NetBIOS Node Status Query (UDP 137)
	if nbName := queryNetBIOSName(ipStr, timeout); nbName != "" {
		return nbName
	}

	// 2. Intentar Reverse DNS (PTR)
	names, err := net.LookupAddr(ipStr)
	if err == nil && len(names) > 0 {
		clean := strings.TrimSuffix(names[0], ".")
		return clean
	}

	return ""
}

// queryNetBIOSName envía un paquete Node Status Request a la IP en el puerto UDP 137.
func queryNetBIOSName(ip string, timeout time.Duration) string {
	conn, err := net.DialTimeout("udp", net.JoinHostPort(ip, "137"), timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	// Paquete NBNS Node Status Request estándar (50 bytes)
	req := []byte{
		0x13, 0x37, // Transaction ID
		0x00, 0x00, // Flags (Query estándar)
		0x00, 0x01, // Questions = 1
		0x00, 0x00, // Answer RRs = 0
		0x00, 0x00, // Authority RRs = 0
		0x00, 0x00, // Additional RRs = 0
		// Nombre codificado NetBIOS wildcard: '*'
		0x20, 0x43, 0x4b, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x00,
		0x00, 0x21, // Type: NBSTAT (Node Status)
		0x00, 0x01, // Class: IN
	}

	if _, err := conn.Write(req); err != nil {
		return ""
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n < 57 {
		return ""
	}

	numNames := int(buf[56])
	offset := 57
	for i := 0; i < numNames && offset+18 <= n; i++ {
		nameBytes := buf[offset : offset+15]
		nameType := buf[offset+15]
		offset += 18

		// 0x00 = Workstation/Redirector, 0x20 = Server service (nombre principal del equipo)
		if nameType == 0x00 || nameType == 0x20 {
			name := strings.TrimSpace(string(bytes.TrimRight(nameBytes, "\x00 ")))
			if name != "" && !strings.HasPrefix(name, "IS~") {
				return name
			}
		}
	}

	return ""
}

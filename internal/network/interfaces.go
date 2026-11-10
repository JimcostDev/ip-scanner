package network

import (
	"fmt"
	"net"
	"strings"

	"ip-scanner/internal/models"
)

// ListInterfaces devuelve todas las interfaces IPv4 activas disponibles.
func ListInterfaces() ([]models.InterfaceInfo, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("error enumerando interfaces: %w", err)
	}

	var result []models.InterfaceInfo

	for _, iface := range ifaces {
		// Ignorar interfaces caídas o loopback
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			ipv4 := ipNet.IP.To4()
			if ipv4 == nil {
				continue // Ignorar IPv6
			}

			// Descartar APIPA (169.254.x.x)
			if ipv4[0] == 169 && ipv4[1] == 254 {
				continue
			}

			info := models.InterfaceInfo{
				Index:        iface.Index,
				Name:         iface.Name,
				HardwareAddr: iface.HardwareAddr,
				IP:           ipv4,
				Netmask:      ipNet.Mask,
				Network:      ipNet,
				IsActive:     true,
				IsLoopback:   false,
			}
			result = append(result, info)
		}
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("no se encontraron interfaces IPv4 activas")
	}

	return result, nil
}

// GetDefaultInterface selecciona la interfaz más apropiada (preferiblemente Ethernet o Wi-Fi).
func GetDefaultInterface(ifaceName string) (*models.InterfaceInfo, error) {
	ifaces, err := ListInterfaces()
	if err != nil {
		return nil, err
	}

	if ifaceName != "" {
		for _, iface := range ifaces {
			if strings.EqualFold(iface.Name, ifaceName) {
				return &iface, nil
			}
		}
		return nil, fmt.Errorf("interfaz '%s' no encontrada", ifaceName)
	}

	// Si sólo hay una, devolverla
	if len(ifaces) == 1 {
		return &ifaces[0], nil
	}

	// Priorizar interfaces Ethernet físicas sobre Wi-Fi o virtuales
	for _, iface := range ifaces {
		lower := strings.ToLower(iface.Name)
		if strings.Contains(lower, "ethernet") && !strings.Contains(lower, "vethernet") && !strings.Contains(lower, "virtual") {
			return &iface, nil
		}
	}

	// Devolver la primera activa
	return &ifaces[0], nil
}

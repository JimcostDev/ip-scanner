package oui

import (
	"fmt"
	"net"
)

// Base de datos de OUIs (primeros 3 bytes de MAC) de fabricantes habituales en TPV/hostelería
var ouiDatabase = map[string]string{
	// Dispositivos específicos de Retail y Hostelería
	"00:17:FC": "Dibal S.A. (Balanza/Cajón)",
	"00:00:48": "Epson Corp (Impresora Tickets)",
	"00:26:AB": "Epson Corp (Impresora Tickets)",
	"00:03:7A": "Taiyo Yuden / Star Micronics",
	"00:11:62": "Star Micronics (Impresora)",
	"00:15:99": "Bixolon Co., Ltd. (Impresora)",
	"00:24:60": "Bixolon Co., Ltd. (Impresora)",
	"00:0E:C6": "Asix Electronics (Adaptador USB-Ethernet)",
	"00:19:99": "Fujitsu Technology Solutions",
	"00:47:50": "Ingenico (Terminal Pago/Datáfono)",
	"00:0B:4F": "VeriFone Inc (Terminal Pago/Datáfono)",
	"F4:B5:20": "PAX Computer Technology (Datáfono)",

	// Equipos TPV, Placas y Tarjetas de Red (Intel, Realtek, HP, Dell, Lenovo)
	"30:13:8B": "Intel Corporate",
	"00:1F:B5": "Intel Corporate",
	"98:90:96": "Dell Inc.",
	"B0:83:FE": "Hewlett Packard Enterprise",
	"44:39:C4": "Hewlett Packard",
	"74:5D:22": "Dell Inc.",
	"50:65:F3": "Intel Corporate",
	"44:A8:C2": "Lenovo Group Ltd.",
	"00:E0:4C": "Realtek Semiconductor",
	"DC:46:28": "Realtek Semiconductor",
	"A0:AD:9F": "Realtek Semiconductor",
	"B8:27:EB": "Raspberry Pi Foundation",
	"DC:A6:32": "Raspberry Pi Foundation",
	"E4:5F:01": "Raspberry Pi Foundation",

	// Routers, Switches y Puntos de Acceso (Cisco, Ubiquiti, TP-Link, MikroTik, Zyxel)
	"6C:7D:B7": "Cisco Systems",
	"00:1A:A1": "Cisco Systems",
	"00:15:6D": "Ubiquiti Networks",
	"24:A4:3C": "Ubiquiti Networks",
	"B4:FB:E4": "Ubiquiti Networks",
	"F0:9F:C2": "Ubiquiti Networks",
	"18:E8:29": "Ubiquiti Networks",
	"50:C7:BF": "TP-Link Technologies",
	"60:32:B1": "TP-Link Technologies",
	"B0:4E:26": "TP-Link Technologies",
	"D8:07:B6": "TP-Link Technologies",
	"14:4F:D7": "MikroTik",
	"48:8F:5A": "MikroTik",
	"64:00:6A": "Zyxel Communications",
	"1C:70:C9": "Zyxel Communications",
	"0C:EA:14": "Huawei Technologies",
	"F4:8E:38": "Huawei Technologies",
	"38:43:7D": "Sercomm Corporation (Router Operador)",
	"7C:03:D8": "Sagemcom Broadband (Router Operador)",
	"F4:3E:61": "Mitrastar Technology (Router Movistar)",

	// Dispositivos Móviles (Camareros, Smartphones, Tablets)
	"00:17:88": "Philips Lighting",
	"04:7C:16": "Apple Inc.",
	"08:8F:C3": "Apple Inc.",
	"AC:BC:32": "Apple Inc.",
	"F0:18:98": "Apple Inc.",
	"70:3E:AC": "Apple Inc.",
	"F8:FF:C2": "Apple Inc.",
	"00:26:37": "Samsung Electronics",
	"28:6C:07": "Samsung Electronics",
	"5C:A3:9D": "Samsung Electronics",
	"74:A7:22": "Xiaomi Communications",
	"64:A2:00": "Xiaomi Communications",
}

// LookupVendor busca el fabricante asociado a una dirección MAC.
// Si no se encuentra, retorna una cadena vacía.
func LookupVendor(mac net.HardwareAddr) string {
	if len(mac) < 3 {
		return ""
	}

	prefix := fmt.Sprintf("%02X:%02X:%02X", mac[0], mac[1], mac[2])
	if vendor, found := ouiDatabase[prefix]; found {
		return vendor
	}

	return ""
}

package network

import (
	"encoding/binary"
	"fmt"
	"net"
)

// SubnetDetails contiene información calculada sobre una subred.
type SubnetDetails struct {
	NetworkIP    net.IP
	BroadcastIP  net.IP
	FirstHostIP  net.IP
	LastHostIP   net.IP
	TotalHosts   int
	CIDRMask     int
	HostIPs      []net.IP
}

// CalculateSubnet calcula los límites y la lista de direcciones utilizables de una red.
func CalculateSubnet(ipNet *net.IPNet) (*SubnetDetails, error) {
	ipv4 := ipNet.IP.To4()
	if ipv4 == nil {
		return nil, fmt.Errorf("dirección IPv4 no válida")
	}

	mask := ipNet.Mask
	if len(mask) != 4 {
		return nil, fmt.Errorf("máscara de red no válida")
	}

	cidr, bits := mask.Size()
	if bits != 32 {
		return nil, fmt.Errorf("máscara IPv4 inválida")
	}

	// Advertencia o control para redes gigantes (ej. /16 = 65534 hosts)
	if cidr < 22 {
		return nil, fmt.Errorf("la máscara /%d contiene demasiadas direcciones (>1022). Por seguridad, limite el rango a /24 o use un rango específico", cidr)
	}

	ipUint := binary.BigEndian.Uint32(ipv4)
	maskUint := binary.BigEndian.Uint32(mask)

	networkUint := ipUint & maskUint
	broadcastUint := networkUint | (^maskUint)

	// Primer host = red + 1, Último host = broadcast - 1
	var firstHostUint, lastHostUint uint32
	var totalHosts int

	if cidr >= 31 {
		// En /31 y /32 no hay rango estándar de hosts utilizables
		firstHostUint = networkUint
		lastHostUint = broadcastUint
		totalHosts = int(broadcastUint - networkUint + 1)
	} else {
		firstHostUint = networkUint + 1
		lastHostUint = broadcastUint - 1
		totalHosts = int(lastHostUint - firstHostUint + 1)
	}

	netIP := make(net.IP, 4)
	binary.BigEndian.PutUint32(netIP, networkUint)

	bcastIP := make(net.IP, 4)
	binary.BigEndian.PutUint32(bcastIP, broadcastUint)

	firstIP := make(net.IP, 4)
	binary.BigEndian.PutUint32(firstIP, firstHostUint)

	lastIP := make(net.IP, 4)
	binary.BigEndian.PutUint32(lastIP, lastHostUint)

	var hostIPs []net.IP
	for u := firstHostUint; u <= lastHostUint; u++ {
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, u)
		hostIPs = append(hostIPs, ip)
	}

	return &SubnetDetails{
		NetworkIP:   netIP,
		BroadcastIP: bcastIP,
		FirstHostIP: firstIP,
		LastHostIP:  lastIP,
		TotalHosts:  totalHosts,
		CIDRMask:    cidr,
		HostIPs:     hostIPs,
	}, nil
}

package scanner

import (
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"time"
	"unsafe"
)

var (
	modiphlpapi = syscall.NewLazyDLL("iphlpapi.dll")
	procSendARP = modiphlpapi.NewProc("SendARP")
)

// SendARP envía una solicitud ARP activa a la dirección IPv4 de destino mediante la API nativa de Windows.
// Retorna la dirección MAC encontrada, el tiempo transcurrido y un booleano indicando si respondió.
func SendARP(targetIP net.IP) (net.HardwareAddr, time.Duration, bool, error) {
	ipv4 := targetIP.To4()
	if ipv4 == nil {
		return nil, 0, false, fmt.Errorf("no es una dirección IPv4 válida")
	}

	destIPUint := binary.LittleEndian.Uint32(ipv4)
	var macBuf [6]byte
	macLen := uint32(len(macBuf))

	start := time.Now()
	ret, _, err := procSendARP.Call(
		uintptr(destIPUint),
		0, // 0 indica usar la dirección de la interfaz adecuada automáticamente
		uintptr(unsafe.Pointer(&macBuf[0])),
		uintptr(unsafe.Pointer(&macLen)),
	)
	elapsed := time.Since(start)

	// Código 0 = NO_ERROR (Host respondió afirmativamente con ARP Reply)
	if ret == 0 {
		mac := make(net.HardwareAddr, 6)
		copy(mac, macBuf[:6])
		return mac, elapsed, true, nil
	}

	// Código 67 = ERROR_BAD_NET_NAME (El host no respondió a las solicitudes ARP en el segmento local)
	if ret == 67 || ret == 31 {
		return nil, elapsed, false, nil
	}

	return nil, elapsed, false, fmt.Errorf("SendARP error Win32 code %d: %w", ret, err)
}

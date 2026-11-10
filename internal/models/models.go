package models

import (
	"net"
	"time"
)

// IPState define el estado de una dirección IP analizada.
type IPState string

const (
	StateOccupied     IPState = "OCUPADA"
	StateFree         IPState = "LIBRE"
	StateUndetermined IPState = "NO DETERMINADA"
)

// DetectionMethod indica cómo se detectó el estado.
type DetectionMethod string

const (
	MethodARP       DetectionMethod = "ARP"
	MethodLocal     DetectionMethod = "LOCAL (Este equipo)"
	MethodGateway   DetectionMethod = "GATEWAY (Router)"
	MethodNone      DetectionMethod = "Sin respuesta"
	MethodError     DetectionMethod = "Error de red"
)

// InterfaceInfo contiene información sobre un adaptador de red.
type InterfaceInfo struct {
	Index        int
	Name         string
	HardwareAddr net.HardwareAddr
	IP           net.IP
	Netmask      net.IPMask
	Network      *net.IPNet
	IsActive     bool
	IsLoopback   bool
}

// HostResult almacena el resultado del escaneo de una dirección IP.
type HostResult struct {
	IP          net.IP
	State       IPState
	MAC         net.HardwareAddr
	Vendor      string
	Hostname    string
	Method      DetectionMethod
	ResponseTime time.Duration
}

// ScanSummary contiene las estadísticas globales de un escaneo.
type ScanSummary struct {
	TotalScanned   int
	TotalOccupied  int
	TotalFree      int
	TotalUndetermined int
	Duration       time.Duration
}

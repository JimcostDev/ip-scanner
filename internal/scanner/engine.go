package scanner

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"ip-scanner/internal/models"
	"ip-scanner/internal/oui"
)

// ProgressCallback se invoca cada vez que se completa el análisis de una dirección IP.
type ProgressCallback func(completed int, total int, result models.HostResult)

// EngineOptions configura los parámetros de ejecución del escáner.
type EngineOptions struct {
	Workers      int
	LocalIP      net.IP
	LocalMAC     net.HardwareAddr
	GatewayIP    net.IP
	ResolveNames bool
}

// DefaultEngineOptions retorna opciones recomendadas por defecto.
func DefaultEngineOptions() EngineOptions {
	return EngineOptions{
		Workers:      40,
		ResolveNames: true,
	}
}

// ScanSubnet ejecuta el escaneo concurrente de las IPs proporcionadas.
func ScanSubnet(ctx context.Context, ips []net.IP, opts EngineOptions, onProgress ProgressCallback) ([]models.HostResult, models.ScanSummary) {
	startTime := time.Now()
	total := len(ips)
	results := make([]models.HostResult, total)

	if opts.Workers <= 0 {
		opts.Workers = 40
	}

	sem := make(chan struct{}, opts.Workers)
	var wg sync.WaitGroup
	var completedCount int64

	var occupiedCount int64
	var freeCount int64
	var undeterminedCount int64

	for idx, ip := range ips {
		wg.Add(1)
		go func(i int, targetIP net.IP) {
			defer wg.Done()

			// Adquirir token del semáforo respetando cancelación de contexto
			select {
			case <-ctx.Done():
				results[i] = models.HostResult{
					IP:     targetIP,
					State:  models.StateUndetermined,
					Method: models.MethodError,
				}
				atomic.AddInt64(&undeterminedCount, 1)
				return
			case sem <- struct{}{}:
			}
			defer func() { <-sem }()

			res := scanSingleHost(targetIP, opts)
			results[i] = res

			switch res.State {
			case models.StateOccupied:
				atomic.AddInt64(&occupiedCount, 1)
			case models.StateFree:
				atomic.AddInt64(&freeCount, 1)
			default:
				atomic.AddInt64(&undeterminedCount, 1)
			}

			done := atomic.AddInt64(&completedCount, 1)
			if onProgress != nil {
				onProgress(int(done), total, res)
			}
		}(idx, ip)
	}

	wg.Wait()
	duration := time.Since(startTime)

	summary := models.ScanSummary{
		TotalScanned:      total,
		TotalOccupied:     int(occupiedCount),
		TotalFree:         int(freeCount),
		TotalUndetermined: int(undeterminedCount),
		Duration:          duration,
	}

	return results, summary
}

func scanSingleHost(ip net.IP, opts EngineOptions) models.HostResult {
	// 1. Caso especial: ¿Es la IP local del propio equipo TPV?
	if opts.LocalIP != nil && ip.Equal(opts.LocalIP) {
		vendor := ""
		if opts.LocalMAC != nil {
			vendor = oui.LookupVendor(opts.LocalMAC)
		}
		hostname := ""
		if opts.ResolveNames {
			hostname = ResolveHostname(ip, 200*time.Millisecond)
		}
		return models.HostResult{
			IP:       ip,
			State:    models.StateOccupied,
			MAC:      opts.LocalMAC,
			Vendor:   vendor,
			Hostname: hostname,
			Method:   models.MethodLocal,
		}
	}

	// 2. Consulta ARP activa (SendARP)
	mac, rtt, answered, err := SendARP(ip)
	if err != nil {
		// Error inesperado en el adaptador
		return models.HostResult{
			IP:           ip,
			State:        models.StateUndetermined,
			Method:       models.MethodError,
			ResponseTime: rtt,
		}
	}

	if answered && mac != nil {
		method := models.MethodARP
		if opts.GatewayIP != nil && ip.Equal(opts.GatewayIP) {
			method = models.MethodGateway
		}

		vendor := oui.LookupVendor(mac)
		hostname := ""
		if opts.ResolveNames {
			hostname = ResolveHostname(ip, 300*time.Millisecond)
		}

		return models.HostResult{
			IP:           ip,
			State:        models.StateOccupied,
			MAC:          mac,
			Vendor:       vendor,
			Hostname:     hostname,
			Method:       method,
			ResponseTime: rtt,
		}
	}

	// 3. No hubo respuesta ARP en L2 local -> Se clasifica como LIBRE en este instante
	return models.HostResult{
		IP:           ip,
		State:        models.StateFree,
		Method:       models.MethodNone,
		ResponseTime: rtt,
	}
}

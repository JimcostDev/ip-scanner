package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"ip-scanner/internal/models"
	"ip-scanner/internal/network"
	"ip-scanner/internal/scanner"
)

func main() {
	exitCode := run()
	os.Exit(exitCode)
}

func run() int {
	ifaceFlag := flag.String("i", "", "Nombre de la interfaz de red a utilizar")
	workersFlag := flag.Int("w", 40, "Número de peticiones concurrentes simultáneas")
	onlyFreeFlag := flag.Bool("only-free", false, "Mostrar únicamente direcciones libres")
	onlyOccupiedFlag := flag.Bool("only-occupied", false, "Mostrar únicamente direcciones ocupadas")
	noNamesFlag := flag.Bool("no-names", false, "Desactivar resolución de nombres para mayor velocidad")
	listIfacesFlag := flag.Bool("list-ifaces", false, "Listar interfaces de red disponibles y salir")
	noPauseFlag := flag.Bool("no-pause", false, "Desactivar pausa final interactiva (para scripts/automatizaciones)")

	flag.Parse()

	// Control de estado para la pausa final
	success := false
	defer func() {
		if !*noPauseFlag && isInteractive() {
			waitPrompt(success)
		}
	}()

	// Listar interfaces si se solicitó
	if *listIfacesFlag {
		ifaces, err := network.ListInterfaces()
		if err != nil {
			fmt.Fprintf(os.Stderr, "[ERROR] %v\n", err)
			return 1
		}
		fmt.Println("Interfaces IPv4 disponibles:")
		for _, iface := range ifaces {
			fmt.Printf(" - %-25s IP: %-15s Red: %s (MAC: %s)\n",
				iface.Name, iface.IP, iface.Network.String(), iface.HardwareAddr)
		}
		success = true
		return 0
	}

	fmt.Println("================================================================================")
	fmt.Println("                    IP SCANNER - DIAGNÓSTICO DE RED LOCAL                       ")
	fmt.Println("================================================================================")

	// 1. Obtener la interfaz de red
	iface, err := network.GetDefaultInterface(*ifaceFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] No se pudo obtener la interfaz de red: %v\n", err)
		return 1
	}

	// 2. Calcular subred
	subnet, err := network.CalculateSubnet(iface.Network)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR] Cálculo de subred fallido: %v\n", err)
		return 1
	}

	fmt.Printf("[i] Interfaz activa:   %s\n", iface.Name)
	fmt.Printf("[i] IP de este equipo: %s (MAC: %s)\n", iface.IP, iface.HardwareAddr)
	fmt.Printf("[i] Subred detectada:  %s (/ %d)\n", subnet.NetworkIP, subnet.CIDRMask)
	fmt.Printf("[i] Rango escaneable:  %s - %s (%d hosts utilizables)\n",
		subnet.FirstHostIP, subnet.LastHostIP, subnet.TotalHosts)
	fmt.Printf("[i] Concurrencia:      %d workers\n", *workersFlag)
	fmt.Println("--------------------------------------------------------------------------------")
	fmt.Println("Iniciando escaneo... Por favor, espere.")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Capturar Ctrl+C para cancelación ordenada
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\n[!] Interrupción recibida. Cancelando escaneo...")
		cancel()
	}()

	opts := scanner.EngineOptions{
		Workers:      *workersFlag,
		LocalIP:      iface.IP,
		LocalMAC:     iface.HardwareAddr,
		ResolveNames: !*noNamesFlag,
	}

	// Gateway estimado común (.1 en la misma red)
	gwIP := make(net.IP, 4)
	copy(gwIP, subnet.NetworkIP.To4())
	gwIP[3] = 1
	opts.GatewayIP = gwIP

	// Callback de progreso en consola
	var lastReport time.Time
	onProgress := func(completed int, total int, res models.HostResult) {
		now := time.Now()
		if now.Sub(lastReport) > 400*time.Millisecond || completed == total {
			lastReport = now
			pct := (float64(completed) / float64(total)) * 100.0
			fmt.Printf("\rProgreso: [%3.0f%%] (%d/%d direcciones analizadas)", pct, completed, total)
		}
	}

	results, summary := scanner.ScanSubnet(ctx, subnet.HostIPs, opts, onProgress)
	fmt.Println() // Salto de línea tras barra de progreso

	// Ordenar resultados numéricamente por IP
	sort.Slice(results, func(i, j int) bool {
		return bytesCompare(results[i].IP.To4(), results[j].IP.To4()) < 0
	})

	fmt.Println("================================================================================")
	fmt.Println("                           RESULTADOS DEL ANÁLISIS                              ")
	fmt.Println("================================================================================")

	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "DIRECCIÓN IP\tESTADO\tMAC ADDRESS\tFABRICANTE (OUI)\tNOMBRE / EQUIPO\tMÉTODO")
	fmt.Fprintln(w, "------------\t------\t-----------\t----------------\t---------------\t------")

	var freeIPs []string

	for _, res := range results {
		if *onlyFreeFlag && res.State != models.StateFree {
			continue
		}
		if *onlyOccupiedFlag && res.State != models.StateOccupied {
			continue
		}

		macStr := "-"
		if res.MAC != nil {
			macStr = res.MAC.String()
		}

		vendorStr := "-"
		if res.Vendor != "" {
			vendorStr = res.Vendor
		}

		hostStr := "-"
		if res.Hostname != "" {
			hostStr = res.Hostname
		}

		if res.State == models.StateFree {
			freeIPs = append(freeIPs, res.IP.String())
		}

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			res.IP.String(), res.State, macStr, vendorStr, hostStr, res.Method)
	}
	w.Flush()

	fmt.Println("--------------------------------------------------------------------------------")
	fmt.Println("RESUMEN GENERAL:")
	fmt.Printf(" - Direcciones analizadas: %d\n", summary.TotalScanned)
	fmt.Printf(" - Direcciones OCUPADAS:   %d\n", summary.TotalOccupied)
	fmt.Printf(" - Direcciones LIBRES:     %d\n", summary.TotalFree)
	if summary.TotalUndetermined > 0 {
		fmt.Printf(" - NO DETERMINADAS:        %d\n", summary.TotalUndetermined)
	}
	fmt.Printf(" - Tiempo total:           %v\n", summary.Duration.Round(time.Millisecond))

	// Recomendaciones generales para configuración de dispositivos
	fmt.Println("================================================================================")
	fmt.Println("             RECOMENDACIONES PARA CONFIGURACIÓN DE DISPOSITIVOS                 ")
	fmt.Println("================================================================================")
	fmt.Println(" - Los resultados reflejan el estado activo en el momento exacto del análisis.")
	fmt.Println(" - Verifique que ningún equipo esté apagado con una dirección estática asignada.")
	fmt.Println(" - Se recomienda asignar direcciones libres fuera del rango DHCP dinámico del router.")

	if len(freeIPs) > 0 {
		var highRangeFree []string
		for _, f := range freeIPs {
			ip := net.ParseIP(f).To4()
			if ip != nil && ip[3] >= 150 && ip[3] <= 245 {
				highRangeFree = append(highRangeFree, f)
			}
		}

		if len(highRangeFree) > 0 {
			showCount := len(highRangeFree)
			if showCount > 6 {
				showCount = 6
			}
			fmt.Printf(" - Direcciones candidatas recomendadas (rango alto libre): %s\n",
				strings.Join(highRangeFree[:showCount], ", "))
		}
	}
	fmt.Println("================================================================================")

	success = true
	return 0
}

func isInteractive() bool {
	stat, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return (stat.Mode() & os.ModeCharDevice) != 0
}

func waitPrompt(success bool) {
	fmt.Println()
	fmt.Println("========================================")
	if success {
		fmt.Println("ESCANEO FINALIZADO")
	} else {
		fmt.Println("EJECUCIÓN FINALIZADA")
	}
	fmt.Println("[ENTER] Cerrar aplicación")
	fmt.Println("========================================")
	fmt.Print("Pulsa ENTER para salir...")

	reader := bufio.NewReader(os.Stdin)
	_, _ = reader.ReadString('\n')
}

func bytesCompare(a, b []byte) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	return len(a) - len(b)
}

package network

import (
	"context"
	"fmt"
	"time"

	"github.com/Ullaakut/nmap/v3"
)

type PortResult struct {
	ID       uint16
	Protocol string
	State    string
	Service  string
	Reason   string
}

type HostResult struct {
	Address string
	Status  string
	Ports   []PortResult
}

type NmapResult struct {
	Target  string
	Profile string
	Hosts   []HostResult
	Stats   string
}

func RunNmapScan(target, profile string) (*NmapResult, error) {
	// Definimos un timeout prudencial según el perfil (60 segundos por seguridad web)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	var options []nmap.Option
	options = append(options, nmap.WithTargets(target))

	// Perfiles de escaneo para el SysAdmin
	switch profile {
	case "fast":
		options = append(options, nmap.WithFastMode()) // -F (Top 100 puertos)
	case "service":
		options = append(options, nmap.WithServiceInfo()) // -sV (Detección de versiones)
	default:
		profile = "standard" // Top 1000 puertos por defecto
	}

	scanner, err := nmap.NewScanner(ctx, options...)
	if err != nil {
		return nil, fmt.Errorf("error inicializando scanner nmap: %w", err)
	}

	result, warnings, err := scanner.Run()
	if err != nil {
		return nil, fmt.Errorf("fallo la ejecucion de nmap: %w (warnings: %v)", err, warnings)
	}

	var hosts []HostResult
	for _, host := range result.Hosts {
		if len(host.Addresses) == 0 {
			continue
		}

		hRes := HostResult{
			Address: host.Addresses[0].Addr,
			Status:  host.Status.State,
		}

		for _, port := range host.Ports {
			serviceName := port.Service.Name
			if port.Service.Product != "" {
				serviceName = fmt.Sprintf("%s (%s %s)", port.Service.Name, port.Service.Product, port.Service.Version)
			}

			hRes.Ports = append(hRes.Ports, PortResult{
				ID:       port.ID,
				Protocol: port.Protocol,
				State:    port.State.State,
				Service:  serviceName,
				Reason:   port.State.Reason,
			})
		}
		hosts = append(hosts, hRes)
	}

	stats := fmt.Sprintf("Escaneado en %.2fs // Hosts activos: %d", result.Stats.Finished.Elapsed, len(hosts))

	return &NmapResult{
		Target:  target,
		Profile: profile,
		Hosts:   hosts,
		Stats:   stats,
	}, nil
}

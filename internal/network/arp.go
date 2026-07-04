package network

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
)

type ArpEntry struct {
	IP        string
	HWType    string
	MAC       string
	Interface string
}

// GetInterfaces lista todas las interfaces y subinterfaces VLAN del kernel (excepto Loopback)
func GetInterfaces() ([]string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("error consultando interfaces del kernel: %w", err)
	}

	var names []string
	for _, i := range ifaces {
		// Descartamos la interfaz de bucle local (lo)
		if i.Flags&net.FlagLoopback == 0 {
			names = append(names, i.Name)
		}
	}
	return names, nil
}

// GetArpTable lee /proc/net/arp y filtra por VLAN/interfaz si se especifica
func GetArpTable(filterIface string) ([]ArpEntry, error) {
	file, err := os.Open("/proc/net/arp")
	if err != nil {
		return nil, fmt.Errorf("error abriendo /proc/net/arp: %w", err)
	}
	defer file.Close()

	var entries []ArpEntry
	scanner := bufio.NewScanner(file)

	// Saltar la línea de cabecera (IP address HW type Flags HW address Mask Device)
	if scanner.Scan() {
		_ = scanner.Text()
	}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		fields := strings.Fields(line)
		if len(fields) < 6 {
			continue
		}

		ip := fields[0]
		hwType := fields[1]
		flags := fields[2]
		mac := fields[3]
		device := fields[5]

		// Filtrar entradas incompletas o en resolución (flags 0x0 o MAC nula)
		if flags == "0x0" || mac == "00:00:00:00:00:00" {
			continue
		}

		// Si el usuario seleccionó una interfaz/VLAN específica, filtramos el resto
		if filterIface != "" && device != filterIface {
			continue
		}

		entries = append(entries, ArpEntry{
			IP:        ip,
			HWType:    hwType,
			MAC:       mac,
			Interface: device,
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error de lectura en tabla ARP: %w", err)
	}

	return entries, nil
}

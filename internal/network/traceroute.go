package network

import (
	"bufio"
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type TracerouteHop struct {
	HopNumber int
	Host      string
	IP        string
	RTT1      string
	RTT2      string
	RTT3      string
	Timeout   bool
}

type TracerouteResult struct {
	Target   string
	TargetIP string
	Hops     []TracerouteHop
}

func RunTraceroute(target string) (*TracerouteResult, error) {
	// 45 segundos de timeout para dar margen a saltos lentos o bloqueados
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	// -q 3: tres sondas por salto | -w 2: 2 seg max de espera | -m 20: max 20 saltos (rápido)
	cmd := exec.CommandContext(ctx, "traceroute", "-q", "3", "-w", "2", "-m", "20", target)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("error creando pipe stdout: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("error iniciando traceroute (verificar si está instalado en el SO): %w", err)
	}

	scanner := bufio.NewScanner(stdout)
	res := &TracerouteResult{Target: target}

	// Regex para detectar cabecera: traceroute to google.com (142.250.190.46), 20 hops max...
	reHeader := regexp.MustCompile(`traceroute to \S+ \(([\d\.]+)\)`)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Extraer IP destino del header
		if res.TargetIP == "" {
			if matches := reHeader.FindStringSubmatch(line); len(matches) > 1 {
				res.TargetIP = matches[1]
				continue
			}
		}

		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}

		hopNum, err := strconv.Atoi(fields[0])
		if err != nil {
			continue // No es una línea de salto válida
		}

		hop := TracerouteHop{HopNumber: hopNum}

		// Salto con timeout (* * *)
		if fields[1] == "*" {
			hop.Timeout = true
			hop.Host = "Request Timed Out (ICMP Blocked)"
			hop.IP = "*.*.*.*"
			res.Hops = append(res.Hops, hop)
			continue
		}

		// Parseo estándar: 1 _gateway (192.168.1.1) 1.12 ms 1.05 ms 1.01 ms
		hop.Host = fields[1]
		if len(fields) > 2 {
			hop.IP = strings.Trim(fields[2], "()")
		}

		// Extracción de tiempos ms
		var rtts []string
		for i := 3; i < len(fields); i++ {
			if fields[i] != "ms" && fields[i] != "*" {
				rtts = append(rtts, fields[i]+" ms")
			} else if fields[i] == "*" {
				rtts = append(rtts, "Timeout")
			}
		}

		if len(rtts) > 0 {
			hop.RTT1 = rtts[0]
		}
		if len(rtts) > 1 {
			hop.RTT2 = rtts[1]
		}
		if len(rtts) > 2 {
			hop.RTT3 = rtts[2]
		}

		res.Hops = append(res.Hops, hop)
	}

	// 1. Auditar errores del stream I/O nativo
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error de lectura en el flujo de traceroute: %w", err)
	}

	// 2. Liberar el proceso hijo y capturar fallos de ejecución del binario
	if err := cmd.Wait(); err != nil && len(res.Hops) == 0 {
		return nil, fmt.Errorf("el binario traceroute falló o el host es inalcanzable: %w", err)
	}

	// 3. Validación de payload vacío
	if len(res.Hops) == 0 {
		return nil, fmt.Errorf("no se obtuvieron saltos para '%s'. Target inaccesible o bloqueado", target)
	}

	return res, nil
}

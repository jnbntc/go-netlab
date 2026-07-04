package network

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"time"
)

type WhoisResult struct {
	Target      string
	WhoisServer string
	RawOutput   string
}

func RunWhois(target string) (*WhoisResult, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return nil, fmt.Errorf("objetivo vacío")
	}

	// 1. Consulta inicial al servidor raíz de IANA
	initialServer := "whois.iana.org"
	output, err := queryWhoisServer(target, initialServer)
	if err != nil {
		return nil, fmt.Errorf("error en consulta inicial a %s: %w", initialServer, err)
	}

	finalServer := initialServer

	// 2. Buscar si IANA nos deriva a un Whois Server regional/TLD (referral)
	reRefer := regexp.MustCompile(`(?i)(?:refer|whois):\s*([a-zA-Z0-9\.\-]+)`)
	matches := reRefer.FindStringSubmatch(output)
	if len(matches) > 1 {
		referServer := strings.TrimSpace(matches[1])
		// Si el servidor de referencia es válido y distinto al inicial, saltamos
		if referServer != "" && !strings.Contains(referServer, "rwhois") {
			finalServer = referServer
			refOutput, err := queryWhoisServer(target, finalServer)
			if err == nil && len(strings.TrimSpace(refOutput)) > 0 {
				output = refOutput
			}
		}
	}

	return &WhoisResult{
		Target:      target,
		WhoisServer: finalServer,
		RawOutput:   output,
	}, nil
}

func queryWhoisServer(query, server string) (string, error) {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(server, "43"), 5*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(10 * time.Second))

	// El protocolo Whois (RFC 3912) exige enviar el target seguido de \r\n
	if _, err := fmt.Fprintf(conn, "%s\r\n", query); err != nil {
		return "", err
	}

	var builder strings.Builder
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		_, _ = builder.WriteString(scanner.Text())
		_ = builder.WriteByte('\n')
	}

	if err := scanner.Err(); err != nil && err != io.EOF {
		return "", err
	}

	return builder.String(), nil
}

package network

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"time"
)

type HeaderResult struct {
	URL        string
	StatusCode int
	Status     string
	Proto      string
	Headers    map[string][]string
	IsTLS      bool
	TLSVersion string
	TLSCipher  string
	CertIssuer string
	CertExpiry string
}

func RunHTTPInspect(targetURL string) (*HeaderResult, error) {
	if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
		targetURL = "https://" + targetURL
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		// Evitamos seguir redirecciones ciegamente para poder inspeccionar un 301/302 real
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return nil, fmt.Errorf("URL malformada: %w", err)
	}

	// Simulamos un User-Agent de SysAdmin para evitar bloqueos básicos por WAF
	req.Header.Set("User-Agent", "Netlab-Engine/2.0 (Golang Security Inspector)")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error conectando al endpoint: %w", err)
	}
	defer resp.Body.Close()

	res := &HeaderResult{
		URL:        targetURL,
		StatusCode: resp.StatusCode,
		Status:     resp.Status,
		Proto:      resp.Proto,
		Headers:    resp.Header,
	}

	// Extracción limpia de telemetría criptográfica TLS si aplica
	if resp.TLS != nil {
		res.IsTLS = true
		res.TLSVersion = tlsVersionToString(resp.TLS.Version)
		res.TLSCipher = tlsCipherToString(resp.TLS.CipherSuite)

		if len(resp.TLS.PeerCertificates) > 0 {
			cert := resp.TLS.PeerCertificates[0]
			res.CertIssuer = cert.Issuer.CommonName
			if res.CertIssuer == "" {
				res.CertIssuer = strings.Join(cert.Issuer.Organization, ", ")
			}
			res.CertExpiry = cert.NotAfter.Format("2006-01-02 15:04:05 UTC")
		}
	}

	return res, nil
}

func tlsVersionToString(v uint16) string {
	switch v {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1 (Deprecated)"
	case tls.VersionTLS10:
		return "TLS 1.0 (Deprecated)"
	default:
		return "Unknown TLS"
	}
}

func tlsCipherToString(c uint16) string {
	return tls.CipherSuiteName(c)
}

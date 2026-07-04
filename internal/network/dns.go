package network

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

type DNSRecord struct {
	Type  string
	Value string
}

type DNSResult struct {
	Domain  string
	Records []DNSRecord
}

func RunDNSLookup(domain string) (*DNSResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var records []DNSRecord
	var mu sync.Mutex
	var wg sync.WaitGroup

	// Resolver nativo de Go
	r := &net.Resolver{}

	// Helper para agregar registros de forma segura entre Goroutines
	addRecord := func(recType, val string) {
		mu.Lock()
		records = append(records, DNSRecord{Type: recType, Value: val})
		mu.Unlock()
	}

	// 1. Registros A / AAAA (IPs)
	wg.Add(1)
	go func() {
		defer wg.Done()
		ips, err := r.LookupIPAddr(ctx, domain)
		if err == nil {
			for _, ip := range ips {
				if ip.IP.To4() != nil {
					addRecord("A", ip.IP.String())
				} else {
					addRecord("AAAA", ip.IP.String())
				}
			}
		}
	}()

	// 2. Registros MX (Mail Exchange)
	wg.Add(1)
	go func() {
		defer wg.Done()
		mxs, err := r.LookupMX(ctx, domain)
		if err == nil {
			for _, mx := range mxs {
				addRecord("MX", fmt.Sprintf("%s (Pref: %d)", mx.Host, mx.Pref))
			}
		}
	}()

	// 3. Registros NS (Name Servers)
	wg.Add(1)
	go func() {
		defer wg.Done()
		nss, err := r.LookupNS(ctx, domain)
		if err == nil {
			for _, ns := range nss {
				addRecord("NS", ns.Host)
			}
		}
	}()

	// 4. Registros TXT (SPF, DKIM, DMARC)
	wg.Add(1)
	go func() {
		defer wg.Done()
		txts, err := r.LookupTXT(ctx, domain)
		if err == nil {
			for _, txt := range txts {
				addRecord("TXT", txt)
			}
		}
	}()

	// 5. Registro CNAME
	wg.Add(1)
	go func() {
		defer wg.Done()
		cname, err := r.LookupCNAME(ctx, domain)
		if err == nil && cname != "" && cname != domain+"." {
			addRecord("CNAME", cname)
		}
	}()

	wg.Wait()

	if len(records) == 0 {
		return nil, fmt.Errorf("no se encontraron registros o el dominio '%s' no responde", domain)
	}

	return &DNSResult{Domain: domain, Records: records}, nil
}

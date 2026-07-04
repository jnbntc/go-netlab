package network

import (
	"fmt"
	"time"

	probing "github.com/prometheus-community/pro-bing"
)

// PingResult encapsula las métricas para enviarlas limpias al frontend
type PingResult struct {
	Host        string
	PacketsSent int
	PacketsRecv int
	PacketLoss  float64
	MinRtt      time.Duration
	AvgRtt      time.Duration
	MaxRtt      time.Duration
	RawOutput   []string
}

func RunPing(host string, count int) (*PingResult, error) {
	pinger, err := probing.NewPinger(host)
	if err != nil {
		return nil, fmt.Errorf("error inicializando pinger: %w", err)
	}

	pinger.Count = count
	pinger.Timeout = time.Second * 10
	// Vital para arquitectura web: usa sockets UDP en vez de ICMP crudo (evita requerir root/SUID)
	pinger.SetPrivileged(false)

	var lines []string
	pinger.OnRecv = func(pkt *probing.Packet) {
		lines = append(lines, fmt.Sprintf("%d bytes from %s: icmp_seq=%d time=%v",
			pkt.Nbytes, pkt.IPAddr, pkt.Seq, pkt.Rtt))
	}

	err = pinger.Run()
	if err != nil {
		return nil, fmt.Errorf("fallo la ejecucion del ping: %w", err)
	}

	stats := pinger.Statistics()
	return &PingResult{
		Host:        stats.Addr,
		PacketsSent: stats.PacketsSent,
		PacketsRecv: stats.PacketsRecv,
		PacketLoss:  stats.PacketLoss,
		MinRtt:      stats.MinRtt,
		AvgRtt:      stats.AvgRtt,
		MaxRtt:      stats.MaxRtt,
		RawOutput:   lines,
	}, nil
}

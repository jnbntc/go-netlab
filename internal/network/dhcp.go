package network

import (
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"time"
)

type DHCPOffer struct {
	ServerIP   string
	YourIP     string
	SubnetMask string
	Router     string
	DNS        []string
	LeaseTime  string
}

func RunDHCPDiscover(ifaceName string) ([]DHCPOffer, error) {
	// 1. Resolver interfaz física si se especificó, sino usar el broadcast general
	var lAddr *net.UDPAddr
	if ifaceName != "" {
		iface, err := net.InterfaceByName(ifaceName)
		if err != nil {
			return nil, fmt.Errorf("interfaz '%s' no encontrada: %w", ifaceName, err)
		}
		// Para bindear al puerto 68 en una interfaz específica
		addrs, err := iface.Addrs()
		if err == nil && len(addrs) > 0 {
			ip, _, _ := net.ParseCIDR(addrs[0].String())
			lAddr = &net.UDPAddr{IP: ip.To4(), Port: 68}
		}
	}

	if lAddr == nil {
		lAddr = &net.UDPAddr{IP: net.IPv4zero, Port: 68}
	}

	rAddr := &net.UDPAddr{IP: net.IPv4(255, 255, 255, 255), Port: 67}

	// 2. Abrir socket UDP con capacidad de Broadcast
	conn, err := net.ListenUDP("udp4", lAddr)
	if err != nil {
		return nil, fmt.Errorf("no se pudo abrir el puerto UDP 68 (requiere permisos o el puerto está ocupado por un cliente DHCP del SO): %w", err)
	}
	defer conn.Close()

	var offers []DHCPOffer
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 3. Generar XID aleatorio (Transaction ID) de 4 bytes y MAC falsa de 6 bytes
	xid := make([]byte, 4)
	mac := make([]byte, 6)
	rand.Read(xid)
	rand.Read(mac)
	mac[0] = 0x02 // Marcar como MAC administrada localmente unicast

	// 4. Construir paquete BOOTP/DHCP Discover crudo (mínimo 300 bytes)
	pkt := make([]byte, 300)
	pkt[0] = 0x01 // Opcode: BOOTREQUEST
	pkt[1] = 0x01 // Hardware Type: Ethernet
	pkt[2] = 0x06 // Hardware Address Length: 6
	pkt[3] = 0x00 // Hops: 0
	copy(pkt[4:8], xid)
	// pkt[8:28] = Secs, Flags, Client IP, Your IP, Server IP, Relay IP (quedan en 0x00)
	copy(pkt[28:34], mac) // Client Hardware Address

	// DHCP Magic Cookie (RFC 2132) en offset 236
	copy(pkt[236:240], []byte{0x63, 0x82, 0x53, 0x63})

	// Opciones DHCP
	idx := 240
	// Opción 53: DHCP Message Type = DHCP Discover (1)
	pkt[idx] = 53
	pkt[idx+1] = 1
	pkt[idx+2] = 1
	idx += 3

	// Opción 55: Parameter Request List (pedir Subnet, Router, DNS)
	pkt[idx] = 55
	pkt[idx+1] = 3
	pkt[idx+2] = 1 // Subnet Mask
	pkt[idx+3] = 3 // Router
	pkt[idx+4] = 6 // Domain Name Server
	idx += 5

	// Opción 255: End
	pkt[idx] = 255

	// 5. Enviar Broadcast al puerto 67
	if _, err := conn.WriteToUDP(pkt, rAddr); err != nil {
		return nil, fmt.Errorf("fallo enviando broadcast DHCP: %w", err)
	}

	// 6. Escuchar respuestas concurrentemente hasta el timeout
	buf := make([]byte, 1500)
	for {
		conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, peer, err := conn.ReadFromUDP(buf)
		if err != nil {
			// Si se venció el deadline global del contexto o no hay más paquetes, salimos
			if ctx.Err() != nil || len(offers) > 0 {
				break
			}
			continue
		}

		if n < 240 {
			continue // Paquete muy corto para ser DHCP
		}

		// Verificar que sea una respuesta (BOOTREPLY = 2) y coincida nuestro XID
		if buf[0] == 0x02 && string(buf[4:8]) == string(xid) {
			offer := parseDHCPOffer(buf[:n], peer.IP.String())
			offers = append(offers, offer)
		}
	}

	if len(offers) == 0 {
		return nil, fmt.Errorf("no se recibieron ofertas DHCP en 5 segundos (verificar firewall o si hay servidores DHCP en la VLAN)")
	}

	return offers, nil
}

func parseDHCPOffer(pkt []byte, peerIP string) DHCPOffer {
	offer := DHCPOffer{
		ServerIP: peerIP,
		YourIP:   net.IP(pkt[16:20]).String(),
	}

	// Recorrer opciones a partir del offset 240
	idx := 240
	for idx < len(pkt) {
		opt := pkt[idx]
		if opt == 255 { // End
			break
		}
		if opt == 0 { // Pad
			idx++
			continue
		}
		if idx+1 >= len(pkt) {
			break
		}
		length := int(pkt[idx+1])
		if idx+2+length > len(pkt) {
			break
		}
		val := pkt[idx+2 : idx+2+length]

		switch opt {
		case 1: // Subnet Mask
			if length == 4 {
				offer.SubnetMask = net.IP(val).String()
			}
		case 3: // Router
			if length >= 4 {
				offer.Router = net.IP(val[:4]).String()
			}
		case 6: // DNS
			for i := 0; i+4 <= length; i += 4 {
				offer.DNS = append(offer.DNS, net.IP(val[i:i+4]).String())
			}
		case 51: // IP Address Lease Time
			if length == 4 {
				secs := uint32(val[0])<<24 | uint32(val[1])<<16 | uint32(val[2])<<8 | uint32(val[3])
				offer.LeaseTime = fmt.Sprintf("%d horas", secs/3600)
			}
		}
		idx += 2 + length
	}
	return offer
}

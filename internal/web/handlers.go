package web

import (
	"html/template"
	"net/http"
	"strconv"

	"github.com/jnbntc/go-netlab/internal/network"
)

type Tool struct {
	Name  string
	File  string
	Desc  string
	Badge string
}

type Handlers struct {
	tpl   *template.Template
	tools []Tool
}

func NewHandlers() *Handlers {
	tpl := template.Must(template.ParseGlob("web/templates/*.html"))

	tools := []Tool{
		{"Ping Avanzado", "/ping", "Verifica conectividad y latencia con un host usando paquetes ICMP.", "L3 ICMP"},
		{"Traceroute Avanzado", "/traceroute", "Traza la ruta de red completa hasta un host de destino.", "L3 Routing"},
		{"Nmap Scanner", "/nmap", "Descubre puertos, servicios y vulnerabilidades en un objetivo.", "L4/L7 Scan"},
		{"ARP Scan", "/arp", "Inspecciona la tabla de caché L2 del kernel para descubrir dispositivos.", "L2 ARP"},
		{"DHCP Discover", "/dhcp", "Encuentra servidores DHCP activos escuchando en la interfaz.", "UDP Broadcast"},
		{"DNS Lookup", "/dns", "Realiza consultas DNS sobre registros de infraestructura.", "L7 DNS"},
		{"HTTP Headers", "/headers", "Inspecciona las cabeceras de respuesta y seguridad de un endpoint.", "HTTP/S"},
		{"Whois Lookup", "/whois", "Consulta la información de registro de un dominio o bloque IP.", "Registry"},
	}

	return &Handlers{tpl: tpl, tools: tools}
}

func (h *Handlers) Index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	h.tpl.ExecuteTemplate(w, "index.html", struct{ Tools []Tool }{h.tools})
}

func (h *Handlers) Ping(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	countStr := r.URL.Query().Get("count")

	count := 4
	if c, err := strconv.Atoi(countStr); err == nil && c > 0 && c <= 20 {
		count = c
	}

	var data struct {
		Host   string
		Count  int
		Result *network.PingResult
		Error  string
	}
	data.Host = host
	data.Count = count

	if host != "" {
		res, err := network.RunPing(host, count)
		if err != nil {
			data.Error = err.Error()
		} else {
			data.Result = res
		}
	}

	h.tpl.ExecuteTemplate(w, "ping.html", data)
}

func (h *Handlers) Arp(w http.ResponseWriter, r *http.Request) {
	selectedIface := r.URL.Query().Get("iface")

	ifaces, errIface := network.GetInterfaces()
	entries, errArp := network.GetArpTable(selectedIface)

	var data struct {
		SelectedIface string
		Interfaces    []string
		Entries       []network.ArpEntry
		Error         string
	}
	data.SelectedIface = selectedIface
	data.Interfaces = ifaces

	if errIface != nil {
		data.Error = errIface.Error()
	} else if errArp != nil {
		data.Error = errArp.Error()
	} else {
		data.Entries = entries
	}

	h.tpl.ExecuteTemplate(w, "arp.html", data)
}

func (h *Handlers) Dns(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	var data struct {
		Domain string
		Result *network.DNSResult
		Error  string
	}
	data.Domain = domain

	if domain != "" {
		res, err := network.RunDNSLookup(domain)
		if err != nil {
			data.Error = err.Error()
		} else {
			data.Result = res
		}
	}
	h.tpl.ExecuteTemplate(w, "dns.html", data)
}

func (h *Handlers) Headers(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("url")
	var data struct {
		Target string
		Result *network.HeaderResult
		Error  string
	}
	data.Target = target

	if target != "" {
		res, err := network.RunHTTPInspect(target)
		if err != nil {
			data.Error = err.Error()
		} else {
			data.Result = res
		}
	}
	h.tpl.ExecuteTemplate(w, "headers.html", data)
}

func (h *Handlers) Nmap(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	profile := r.URL.Query().Get("profile")
	if profile == "" {
		profile = "fast"
	}

	var data struct {
		Target  string
		Profile string
		Result  *network.NmapResult
		Error   string
	}
	data.Target = target
	data.Profile = profile

	if target != "" {
		res, err := network.RunNmapScan(target, profile)
		if err != nil {
			data.Error = err.Error()
		} else {
			data.Result = res
		}
	}
	h.tpl.ExecuteTemplate(w, "nmap.html", data)
}

func (h *Handlers) Traceroute(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	var data struct {
		Target string
		Result *network.TracerouteResult
		Error  string
	}
	data.Target = target

	if target != "" {
		res, err := network.RunTraceroute(target)
		if err != nil {
			data.Error = err.Error()
		} else {
			data.Result = res
		}
	}
	h.tpl.ExecuteTemplate(w, "traceroute.html", data)
}

func (h *Handlers) Dhcp(w http.ResponseWriter, r *http.Request) {
	iface := r.URL.Query().Get("iface")
	var data struct {
		Iface  string
		Result []network.DHCPOffer
		Error  string
	}
	data.Iface = iface

	// Se dispara al cargar si se presiona el botón
	if r.URL.Query().Has("action") {
		res, err := network.RunDHCPDiscover(iface)
		if err != nil {
			data.Error = err.Error()
		} else {
			data.Result = res
		}
	}
	h.tpl.ExecuteTemplate(w, "dhcp.html", data)
}

func (h *Handlers) Whois(w http.ResponseWriter, r *http.Request) {
	target := r.URL.Query().Get("target")
	var data struct {
		Target string
		Result *network.WhoisResult
		Error  string
	}
	data.Target = target

	if target != "" {
		res, err := network.RunWhois(target)
		if err != nil {
			data.Error = err.Error()
		} else {
			data.Result = res
		}
	}
	h.tpl.ExecuteTemplate(w, "whois.html", data)
}

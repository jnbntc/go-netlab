# go-netlab

A lightweight, high-concurrency network diagnostic and troubleshooting laboratory built in Go. It provides a clean, responsive web interface (`html/template`) over a robust backend designed for local subnet auditing, protocol analysis, and real-time network discovery.

## Features

* **L2 Network Discovery (ARP Scan):** Fast local subnet scanning and MAC mapping leveraging Go worker pools.
* **Port Scanner & Nmap Utilities:** TCP/UDP port enumeration and service discovery.
* **ICMP & Routing Diagnostics:** Real-time **Ping** and **Traceroute** execution with live latency metrics.
* **Protocol Analyzers:**
  * **DNS:** Direct query resolution and record inspection.
  * **DHCP:** Lease discovery and packet diagnostics.
  * **HTTP Headers:** Request/response header inspection and debugging.
  * **Whois:** Domain and ASN lookup utilities.

## Architecture Highlights

* **Zero Frontend Build Step:** Server-side rendered UI using Go standard library templates (`web/templates`). No Node.js, NPM, or heavy JS bundles required.
* **Single Static Binary:** Designed for minimal runtime footprint. Compiles seamlessly to Alpine Linux or bare-metal edge devices without external libraries.
* **Concurrent Execution:** Uses goroutines and context timeouts to prevent deadlocks and connection leaks during aggressive subnet scans.

## Build & Deployment

### Standalone Static Binary (Recommended for Alpine / Edge)
Compile without C dependencies and strip debugging symbols for minimum artifact size:

```bash
CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -trimpath -o go-netlab .
```

### Run Locally

```bash
# Execute the compiled binary
./go-netlab

# Or run directly via Go toolchain
go run main.go
```

By default, the web interface listens on `http://localhost:8080` (or configured port via environment variables).

---

## Security Note
Certain L2 operations (like raw ARP scans or ICMP socket manipulation) require elevated privileges (`CAP_NET_RAW` capability or root access) depending on your host kernel configuration:

```bash
sudo setcap cap_net_raw+ep ./go-netlab
```

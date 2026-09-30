# go-netlab

<p>
  <img src="https://img.shields.io/badge/Go-1.26-00ADD8?style=flat-square&logo=go&logoColor=white" alt="Go" />
  <img src="https://img.shields.io/badge/Networking-Diagnostics-333333?style=flat-square" alt="Network Diagnostics" />
  <img src="https://img.shields.io/badge/Platform-Linux-333333?style=flat-square&logo=linux&logoColor=white" alt="Linux" />
</p>

A lightweight web toolbox for common network diagnostics on Linux, built in Go.

The project keeps the frontend deliberately simple with server-side templates and groups several day-to-day troubleshooting tools behind a single local HTTP service.

> **Goal:** make common network checks available from one small, understandable codebase without adding a frontend build toolchain.

## What it does

| Tool | Implementation |
| --- | --- |
| **Ping** | Uses `pro-bing` in unprivileged mode and reports packet loss plus min/avg/max RTT |
| **ARP** | Reads the Linux kernel ARP cache from `/proc/net/arp`, with optional interface/VLAN filtering |
| **DNS** | Concurrent lookups for A/AAAA, MX, NS, TXT and CNAME records |
| **HTTP / TLS** | Inspects response headers, protocol, TLS version, cipher, certificate issuer and expiry |
| **Nmap** | Runs Nmap profiles for fast, standard or service/version discovery |
| **Traceroute** | Executes the system `traceroute` command and parses hops and RTTs |
| **DHCP Discover** | Sends a DHCP broadcast and collects offers on UDP 68 |
| **Whois** | Queries IANA over TCP/43 and follows a registry referral when available |

## Architecture

```text
cmd/netlab-server/main.go
        │
        ├── internal/web/
        │     ├── router.go
        │     └── handlers.go
        │
        ├── internal/network/
        │     ├── arp.go
        │     ├── dhcp.go
        │     ├── dns.go
        │     ├── headers.go
        │     ├── nmap.go
        │     ├── ping.go
        │     ├── traceroute.go
        │     └── whois.go
        │
        └── web/
              ├── templates/
              └── static/
```

The HTTP server listens on `:8080` and uses Go's standard `net/http` and `html/template` packages.

## Requirements

- Linux
- Go 1.26.x
- `nmap` for the Nmap page
- `traceroute` for traceroute diagnostics

The DHCP discovery tool binds UDP port 68. Depending on the host configuration, this may require elevated privileges, and it can conflict with an OS DHCP client already using that port.

## Build

Run from the repository root:

```bash
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" \
  -o go-netlab ./cmd/netlab-server
```

## Run

The templates and static assets are currently loaded from the `web/` directory at runtime, so start the server from the repository root:

```bash
./go-netlab
```

For development:

```bash
go run ./cmd/netlab-server
```

Then open:

```text
http://localhost:8080
```

## Operational notes

- **ARP is passive:** the current implementation inspects the kernel ARP cache; it does not actively probe the subnet.
- **Ping is unprivileged:** it uses the non-privileged mode provided by `pro-bing`.
- **Nmap and traceroute are external dependencies:** the Go code invokes tooling available on the host.
- **DHCP discovery is the exception:** binding UDP/68 may require additional privileges or a dedicated test environment.

## Security

Some tools in this repository can actively probe network services.

Use them only on systems and networks you own or are explicitly authorized to test. For routine troubleshooting, prefer running the service with the minimum privileges required by the specific diagnostic being used.

## Status

This is a personal network-engineering lab rather than a finished product. The emphasis is on keeping individual diagnostics readable and easy to extend while consolidating frequently used troubleshooting workflows behind one interface.

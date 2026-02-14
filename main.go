package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

type Config struct {
	ListenAddress string
	Port          int
	DoHServer     string
	Timeout       time.Duration
}

type DoHResolver struct {
	config *Config
	client *http.Client
}

func NewDoHResolver(config *Config) *DoHResolver {
	transport := &http.Transport{
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}

	return &DoHResolver{
		config: config,
		client: &http.Client{
			Timeout:   config.Timeout,
			Transport: transport,
		},
	}
}

func (r *DoHResolver) Resolve(query *dns.Msg) (*dns.Msg, error) {
	buf, err := query.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed to pack DNS query: %w", err)
	}

	req, err := http.NewRequestWithContext(
		context.Background(),
		"POST",
		r.config.DoHServer,
		bytes.NewReader(buf),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")
	req.Header.Set("Accept-Encoding", "identity")

	resp, err := r.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("DoH request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("DoH server returned status %d: %s",
			resp.StatusCode, string(body))
	}

	respBuf, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	reply := new(dns.Msg)
	if err := reply.Unpack(respBuf); err != nil {
		return nil, fmt.Errorf("failed to unpack DNS response: %w", err)
	}

	return reply, nil
}

type DNSHandler struct {
	resolver *DoHResolver
}

func (h *DNSHandler) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	clientIP, _, _ := net.SplitHostPort(w.RemoteAddr().String())

	if len(req.Question) > 0 {
		q := req.Question[0]
		log.Printf("[%s] Query: %s (%s)", clientIP, q.Name, dns.TypeToString[q.Qtype])
	}

	reply, err := h.resolver.Resolve(req)
	if err != nil {
		log.Printf("[%s] Resolution error: %v", clientIP, err)
		reply = new(dns.Msg)
		reply.SetReply(req)
		reply.Rcode = dns.RcodeServerFailure
	}

	if err := w.WriteMsg(reply); err != nil {
		log.Printf("[%s] Response send failed: %v", clientIP, err)
	}
}

//
// ===== WINDOWS DNS ADDITION (ONLY NEW CODE) =====
//

// Detect active interface via default route
func getActiveInterface() (*net.Interface, net.IP, error) {
	conn, err := net.Dial("udp", "8.8.8.8:53")
	if err != nil {
		return nil, nil, err
	}
	defer conn.Close()

	localIP := conn.LocalAddr().(*net.UDPAddr).IP

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, err
	}

	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			if ipNet, ok := addr.(*net.IPNet); ok {
				if ipNet.IP.Equal(localIP) {
					return &iface, localIP, nil
				}
			}
		}
	}
	return nil, nil, fmt.Errorf("active interface not found")
}

// Force IPv4 DNS → 127.0.0.1 (Windows)
func setWindowsIPv4DNS(iface *net.Interface) error {
	cmd := exec.Command(
		"netsh",
		"interface",
		"ipv4",
		"set",
		"dnsservers",
		fmt.Sprintf(`name=%s`, iface.Name), 
		"static",
		"127.0.0.1",
		"primary",
	)

	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}


func main() {
	listenAddr := flag.String("listen", "127.0.0.1", "Listen address for DNS server")
	port := flag.Int("port", 5353, "Listen port (use 53 for system-wide DNS - requires admin)")
	dohServer := flag.String("doh", "https://dns.quad9.net/dns-query", "DoH server URL")
	timeout := flag.Duration("timeout", 5*time.Second, "DoH request timeout")
	flag.Parse()

	cleanDoH := strings.TrimSpace(*dohServer)
	if cleanDoH == "" || !strings.HasPrefix(cleanDoH, "https://") {
		log.Fatal("Error: DoH server must be HTTPS and non-empty")
	}


	iface, ip, err := getActiveInterface()
	if err != nil {
		log.Fatalf("Interface detection failed: %v", err)
	}

	log.Printf(" Active interface: %s (Index %d, IP %s)",
		iface.Name, iface.Index, ip)

	if err := setWindowsIPv4DNS(iface); err != nil {
		log.Fatalf("Failed to set IPv4 DNS: %v", err)
	}

	log.Println(" IPv4 DNS set to 127.0.0.1")

	config := &Config{
		ListenAddress: *listenAddr,
		Port:          *port,
		DoHServer:     cleanDoH,
		Timeout:       *timeout,
	}

	resolver := NewDoHResolver(config)
	handler := &DNSHandler{resolver: resolver}

	udpServer := &dns.Server{
		Addr:         fmt.Sprintf("%s:%d", config.ListenAddress, config.Port),
		Net:          "udp",
		Handler:      handler,
		ReadTimeout:  2 * time.Second,
		WriteTimeout: 2 * time.Second,
	}

	tcpServer := &dns.Server{
		Addr:         fmt.Sprintf("%s:%d", config.ListenAddress, config.Port),
		Net:          "tcp",
		Handler:      handler,
		ReadTimeout:  2 * time.Second,
		WriteTimeout: 2 * time.Second,
	}

	go udpServer.ListenAndServe()
	go tcpServer.ListenAndServe()

	log.Printf("Forwarding to DoH server ")

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println(" Shutting down DNS server...")
	_ = udpServer.Shutdown()
	_ = tcpServer.Shutdown()

	log.Println(" DoH proxy stopped")
}

package main

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"strings"
)

const (
	cinsURL     = "http://cinsscore.com/list/ci-badguys.txt"
	spamhausURL = "https://www.spamhaus.org/drop/dropv6.txt"
)

// Executor defines how we send rules to the system
type Executor interface {
	Execute(input string) error
}

// NftExecutor is the production implementation that calls the 'nft' binary
type NftExecutor struct{}

func (n NftExecutor) Execute(input string) error {
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(input)
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func main() {
	// 1. Fetch data from remote sources
	v4List := fetchAndValidate(cinsURL, false)
	v6List := fetchAndValidate(spamhausURL, true)

	// 2. Build the transaction string
	transaction := BuildTransaction(v4List, v6List)

	// 3. Execute using the NftExecutor
	exec := NftExecutor{}
	if err := exec.Execute(transaction); err != nil {
		fmt.Printf("Failed to update nftables: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("Success: Loaded %d IPv4 and %d IPv6 entries.\n", len(v4List), len(v6List))
}

// BuildTransaction creates the actual nftables syntax
func BuildTransaction(v4 []string, v6 []string) string {
	var sb strings.Builder
	sb.WriteString("flush set inet filter cins_blackhole_v4\n")
	for _, ip := range v4 {
		fmt.Fprintf(&sb, "add element inet filter cins_blackhole_v4 { %s }\n", ip)
	}

	sb.WriteString("flush set inet filter spamhaus_blackhole_v6\n")
	for _, ip := range v6 {
		fmt.Fprintf(&sb, "add element inet filter spamhaus_blackhole_v6 { %s }\n", ip)
	}
	return sb.String()
}

// fetchAndValidate handles the HTTP request and parsing
func fetchAndValidate(url string, isV6 bool) []string {
	resp, err := http.Get(url)
	if err != nil {
		fmt.Printf("Error fetching %s: %v\n", url, err)
		return nil
	}
	defer resp.Body.Close()
	return parseList(resp.Body, isV6)
}

// parseList is the internal logic that can be tested with any io.Reader
func parseList(r io.Reader, isV6 bool) []string {
	var valid []string
	scanner := bufio.NewScanner(r)

	for scanner.Scan() {
		raw := scanner.Text()
		if ip, ok := validateLine(raw, isV6); ok {
			valid = append(valid, ip)
		}
	}
	return valid
}

// validateLine performs the strict type-checking for a single string
func validateLine(line string, isV6 bool) (string, bool) {
	line = strings.TrimSpace(line)
	// Skip comments and empty lines
	if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
		return "", false
	}

	// Extract the first field (IP/CIDR)
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return "", false
	}
	rawIP := parts[0]

	// Try parsing as Prefix (CIDR)
	prefix, err := netip.ParsePrefix(rawIP)
	if err != nil {
		// Try parsing as single Addr
		addr, err := netip.ParseAddr(rawIP)
		if err != nil {
			return "", false // Garbage
		}
		prefix = netip.PrefixFrom(addr, addr.BitLen())
	}

	// Ensure protocol family matches
	if isV6 && prefix.Addr().Is6() {
		return prefix.String(), true
	} else if !isV6 && prefix.Addr().Is4() {
		return prefix.String(), true
	}

	return "", false
}

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
	chunkSize   = 500
)

type Executor interface {
	Execute(input string) error
}

type NftExecutor struct{}

func (n NftExecutor) Execute(input string) error {
	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(input)
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func main() {
	v4List := fetchAndValidate(cinsURL, false)
	v6List := fetchAndValidate(spamhausURL, true)

	nft := NftExecutor{}

	// 1. Flush the sets first
	flushCmd := "flush set inet filter cins_blackhole_v4\nflush set inet filter spamhaus_blackhole_v6\n"
	if err := nft.Execute(flushCmd); err != nil {
		fmt.Printf("Failed to flush nftables sets: %v\n", err)
		os.Exit(1)
	}

	// 2. Chunk and load IPv4
	v4Chunks := chunkSlice(v4List, chunkSize)
	for _, chunk := range v4Chunks {
		transaction := BuildTransactionChunk("cins_blackhole_v4", chunk)
		if err := nft.Execute(transaction); err != nil {
			fmt.Printf("Failed loading IPv4 chunk: %v\n", err)
			os.Exit(1)
		}
	}

	// 3. Chunk and load IPv6
	v6Chunks := chunkSlice(v6List, chunkSize)
	for _, chunk := range v6Chunks {
		transaction := BuildTransactionChunk("spamhaus_blackhole_v6", chunk)
		if err := nft.Execute(transaction); err != nil {
			fmt.Printf("Failed loading IPv6 chunk: %v\n", err)
			os.Exit(1)
		}
	}

	fmt.Printf("Success: Loaded %d IPv4 and %d IPv6 entries in chunks of %d.\n", len(v4List), len(v6List), chunkSize)
}

func BuildTransactionChunk(setName string, ips []string) string {
	var sb strings.Builder
	if len(ips) == 0 {
		return ""
	}
	sb.WriteString(fmt.Sprintf("add element inet filter %s { ", setName))
	sb.WriteString(strings.Join(ips, ", "))
	sb.WriteString(" }\n")
	return sb.String()
}

func chunkSlice(slice []string, size int) [][]string {
	var chunks [][]string
	for i := 0; i < len(slice); i += size {
		end := i + size
		if end > len(slice) {
			end = len(slice)
		}
		chunks = append(chunks, slice[i:end])
	}
	return chunks
}

func fetchAndValidate(url string, isV6 bool) []string {
	resp, err := http.Get(url)
	if err != nil {
		fmt.Printf("Error fetching %s: %v\n", url, err)
		return nil
	}
	defer resp.Body.Close()
	return parseList(resp.Body, isV6)
}

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

func validateLine(line string, isV6 bool) (string, bool) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
		return "", false
	}

	parts := strings.Fields(line)
	if len(parts) == 0 {
		return "", false
	}
	rawIP := parts[0]

	prefix, err := netip.ParsePrefix(rawIP)
	if err != nil {
		addr, err := netip.ParseAddr(rawIP)
		if err != nil {
			return "", false
		}
		prefix = netip.PrefixFrom(addr, addr.BitLen())
	}

	if isV6 && prefix.Addr().Is6() {
		return prefix.String(), true
	} else if !isV6 && prefix.Addr().Is4() {
		return prefix.String(), true
	}

	return "", false
}

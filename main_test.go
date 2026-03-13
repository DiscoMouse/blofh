package main

import (
	"strings"
	"testing"
)

func TestParsePrefix(t *testing.T) {
	input := `
# Standard IP
1.1.1.1
; A comment with an IP
2.2.2.2 
# Garbage that should be ignored
not-an-ip
123.456.789.0
# CIDR notation
192.168.1.0/24
# Mixed IPv6 in IPv4 list
2001:db8::1
`
	var found []string
	lines := strings.Split(input, "\n")
	for _, line := range lines {
		if ip, ok := validateLine(line, false); ok {
			found = append(found, ip)
		}
	}

	expectedCount := 3
	if len(found) != expectedCount {
		t.Errorf("Expected %d IPs, got %d. Found: %v", expectedCount, len(found), found)
	}

	// Verify the parser correctly standardizes everything to CIDR notation
	expectedIPs := []string{"1.1.1.1/32", "2.2.2.2/32", "192.168.1.0/24"}
	for i, v := range found {
		if v != expectedIPs[i] {
			t.Errorf("Expected %s, got %s", expectedIPs[i], v)
		}
	}
}

func TestBuildTransactionChunk(t *testing.T) {
	chunk := []string{"1.2.3.4/32", "5.6.7.8/32"}
	setName := "cins_blackhole_v4"

	result := BuildTransactionChunk(setName, chunk)

	// Verify the syntax correctly groups the chunk into a single element array
	expectedStr := "add element inet filter cins_blackhole_v4 { 1.2.3.4/32, 5.6.7.8/32 }\n"
	if result != expectedStr {
		t.Errorf("Chunk transaction built incorrectly.\nGot: %s\nExpected: %s", result, expectedStr)
	}
}

func TestChunkSlice(t *testing.T) {
	// Test the math logic of our chunking function
	list := []string{"a", "b", "c", "d", "e"}

	// Break 5 items into chunks of 2
	chunks := chunkSlice(list, 2)

	if len(chunks) != 3 {
		t.Fatalf("Expected 3 chunks, got %d", len(chunks))
	}
	if len(chunks[0]) != 2 || chunks[0][0] != "a" {
		t.Errorf("Chunk 0 incorrect: %v", chunks[0])
	}
	if len(chunks[2]) != 1 || chunks[2][0] != "e" {
		t.Errorf("Chunk 2 incorrect: %v", chunks[2])
	}
}

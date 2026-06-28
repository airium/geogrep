package geogrep

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func TestReadSRSStringListRejectsOversizedLength(t *testing.T) {
	var buf bytes.Buffer
	writeUvarintForTest(t, &buf, maxSRSListLength+1)

	_, err := readSRSStringList(bufio.NewReader(&buf))
	if err == nil {
		t.Fatal("expected oversized list length error")
	}
	if !strings.Contains(err.Error(), "SRS string list length too large") {
		t.Fatalf("error=%q want oversized list length", err)
	}
}

func TestReadSRSStringListRejectsOversizedString(t *testing.T) {
	var buf bytes.Buffer
	writeUvarintForTest(t, &buf, 1)
	writeUvarintForTest(t, &buf, maxSRSStringLength+1)

	_, err := readSRSStringList(bufio.NewReader(&buf))
	if err == nil {
		t.Fatal("expected oversized string length error")
	}
	if !strings.Contains(err.Error(), "SRS string length too large") {
		t.Fatalf("error=%q want oversized string length", err)
	}
}

func TestReadSRSIPSetRejectsOversizedRangeCount(t *testing.T) {
	var buf bytes.Buffer
	if err := buf.WriteByte(1); err != nil {
		t.Fatal(err)
	}
	if err := binary.Write(&buf, binary.BigEndian, uint64(maxSRSPrefixRangeCount+1)); err != nil {
		t.Fatal(err)
	}

	_, err := readSRSIPSet(bufio.NewReader(&buf))
	if err == nil {
		t.Fatal("expected oversized IP range count error")
	}
	if !strings.Contains(err.Error(), "SRS IP range count too large") {
		t.Fatalf("error=%q want oversized IP range count", err)
	}
}

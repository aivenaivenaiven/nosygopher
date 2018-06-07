package main

import (
	"bytes"
	"fmt"
	"os"
	"reflect"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

type NosyGopher struct {
	ifaces         []string
	outpath, bpf   string
	quiet, promisc bool
	snapshotLen    int
	timeout        time.Duration
}

type NGResult struct {
	err    error
	packet gopacket.Packet
	dev    string
	writer *pcapgo.Writer
}

type FooImpl struct {
	protocol layers.IPProtocol
}

func (ng *NosyGopher) Sniff() error {
	var chans []<-chan NGResult
	for _, dev := range ng.ifaces {
		chans = append(chans, ng.sniffDevice(dev))
	}

	c := fanin(chans...)
	for res := range c {
		if res.err != nil {
			return res.err
		}

		if !ng.quiet {
			fmt.Println(ng.packetString(res))
		}
		if res.writer != nil {
			res.writer.WritePacket(res.packet.Metadata().CaptureInfo, res.packet.Data())
		}
	}

	return nil
}

func (ng *NosyGopher) sniffDevice(dev string) <-chan NGResult {
	fmt.Printf("nosy gopher is sniffing on %s...\n", dev)
	c := make(chan NGResult)

	go func() {
		// Open device
		handle, err := pcap.OpenLive(dev, int32(ng.snapshotLen), ng.promisc, ng.timeout)
		if err != nil {
			c <- NGResult{packet: nil, writer: nil, dev: dev, err: err}
			return
		}
		defer handle.Close()

		// Set BPFFilter if present
		if ng.bpf != "" {
			if err := handle.SetBPFFilter(ng.bpf); err != nil {
				c <- NGResult{packet: nil, writer: nil, dev: dev, err: err}
				return
			}
		}

		// Create writer if outpath is set
		var writer *pcapgo.Writer
		var f *os.File
		if ng.outpath != "" {
			writer, f = ng.writer(dev, handle)
			defer f.Close()
		}

		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			c <- NGResult{packet: packet, writer: writer, dev: dev, err: nil}
		}
	}()

	return c
}

// Format a packet for printing succinctly
func (ng *NosyGopher) packetString(res NGResult) string {
	// "Dev - Timestamp - PacketLength Protocol SrcIP:SrcPort > DestIP:DstPort

	var b bytes.Buffer

	fmt.Fprintf(&b, "%s -", res.dev)
	if !res.packet.Metadata().Timestamp.IsZero() {
		fmt.Fprintf(&b, " %v -", res.packet.Metadata().Timestamp)
	}

	fmt.Fprintf(&b, " %d bytes", res.packet.Metadata().Length)

	netVal := reflect.ValueOf(res.packet.NetworkLayer())
	transVal := reflect.ValueOf(res.packet.TransportLayer())
	fmt.Fprintf(&b, " %s ", fieldString(netVal, "Protocol"))

	var transBytes bytes.Buffer
	SrcIp, SrcPort := fieldString(netVal, "SrcIP"), fieldString(transVal, "SrcPort")
	DstIp, DstPort := fieldString(netVal, "DstIP"), fieldString(transVal, "DstPort")
	transBytes.WriteString(SrcIp)
	if SrcPort != "" {
		fmt.Fprintf(&transBytes, ":%s", SrcPort)
	}
	if transBytes.Len() > 0 {
		transBytes.WriteString(" > ")
	}
	transBytes.WriteString(DstIp)
	if DstPort != "" {
		fmt.Fprintf(&transBytes, ":%s", DstPort)
	}

	b.WriteString(transBytes.String())
	return b.String()
}

//

// String representation of an aribtrary reflect value field
func fieldString(v reflect.Value, name string) string {
	val := reflect.Indirect(v)
	if !val.IsValid() {
		return ""
	}

	val = val.FieldByName(name)
	if !val.IsValid() {
		return ""
	}

	return fmt.Sprintf("%s", val)
}

// Creates file, writer and writes file header
func (ng *NosyGopher) writer(dev string, handle *pcap.Handle) (*pcapgo.Writer, *os.File) {
	f, _ := os.Create(dev + "_" + ng.outpath)
	w := pcapgo.NewWriter(f)
	w.WriteFileHeader(uint32(ng.snapshotLen), handle.LinkType())
	return w, f
}

// Variadic fanin function
func fanin(inputs ...<-chan NGResult) <-chan NGResult {
	agg := make(chan NGResult)

	for _, ch := range inputs {
		go func(c <-chan NGResult) {
			for msg := range c {
				agg <- msg
			}
		}(ch)
	}

	return agg
}

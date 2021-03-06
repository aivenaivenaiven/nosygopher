package main

import (
	"bytes"
	"fmt"
	"os"
	"reflect"
	"regexp"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

type NosyGopher struct {
	ifaces           []string
	outpath, bpf, re string
	quiet, promisc   bool
	snapshotLen      int
	timeout          time.Duration
}

type NGResult struct {
	err    error
	packet gopacket.Packet
	dev    string
	writer *pcapgo.Writer
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

		if err := ng.handleResult(res); err != nil {
			return err
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

// Handle NGResult from device channel
func (ng *NosyGopher) handleResult(res NGResult) error {
	if ng.re != "" {
		re, err := regexp.Compile(ng.re)
		if err != nil {
			return err
		}

		// Drop result if no match found in payload
		app := res.packet.ApplicationLayer()
		if app == nil || re.Find(app.Payload()) == nil {
			return nil
		}
	}

	if !ng.quiet {
		fmt.Printf("%s - %s\n", res.dev, ng.packetString(res.packet))
	}

	if res.writer != nil {
		res.writer.WritePacket(res.packet.Metadata().CaptureInfo, res.packet.Data())
	}

	return nil
}

// Format a packet for printing succinctly, e.g.
// "Device - Timestamp - PacketLength Protocol SrcIP:SrcPort > DestIP:DstPort
func (ng *NosyGopher) packetString(packet gopacket.Packet) string {
	var b bytes.Buffer

	if !packet.Metadata().Timestamp.IsZero() {
		fmt.Fprintf(&b, " %v -", packet.Metadata().Timestamp)
	}

	fmt.Fprintf(&b, " %d bytes", packet.Metadata().Length)

	netVal := reflect.ValueOf(packet.NetworkLayer())
	transVal := reflect.ValueOf(packet.TransportLayer())
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

	b.Write(transBytes.Bytes())

	return b.String()
}

// Creates file, writer and writes file header
func (ng *NosyGopher) writer(dev string, handle *pcap.Handle) (*pcapgo.Writer, *os.File) {
	f, _ := os.Create(dev + "_" + ng.outpath)
	w := pcapgo.NewWriter(f)
	w.WriteFileHeader(uint32(ng.snapshotLen), handle.LinkType())
	return w, f
}

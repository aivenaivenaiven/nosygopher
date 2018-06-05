package main

import (
	"fmt"
	"os"
	"time"
	"reflect"

	"github.com/google/gopacket"
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

		if !ng.quiet {
			// fmt.Println(res.packet)
			// if app := res.packet.ApplicationLayer(); app != nil {
			// 	fmt.Printf("PAYLOAD: %v\n", string(app.Payload()))
			// }
			if net := res.packet.NetworkLayer(); net != nil {
				fmt.Printf("NETWORK LAYER: %+v\n", net)
				fmt.Printf("OK: %v\n", net.(reflect.TypeOf(net)))
				fmt.Printf("STUFF: %v\n", reflect.TypeOf(net))
				// fmt.Printf("STUFF: %v\n", net.Protocol)
				// for i := 0; i < netType.NumMethod(); i++ {
				//     method := netType.Method(i)
				//     fmt.Println(method.Name)
				// }
			}
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
			c <- NGResult{packet: nil, writer: nil, err: err}
			return
		}
		defer handle.Close()

		// Set BPFFilter if present
		if ng.bpf != "" {
			if err := handle.SetBPFFilter(ng.bpf); err != nil {
				c <- NGResult{packet: nil, writer: nil, err: err}
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
			c <- NGResult{packet: packet, writer: writer, err: nil}
		}
	}()

	return c
}

// Format a packet for printing succinctly
// func (ng *NosyGopher) printPacket(packet gopacket.Packet) {
// 	var srcIP, destIP, proto
// }

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

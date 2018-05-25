package main

import (
    "fmt"
    "time"
    "os"

    "github.com/google/gopacket"
    "github.com/google/gopacket/pcap"
    "github.com/google/gopacket/pcapgo"
)

type NosyGopher struct {
    iface, outpath, bpf string
    quiet, promisc bool
    snapshotLen int
    timeout time.Duration
}

func (ng *NosyGopher) Sniff() error {
    fmt.Printf("nosy gopher is sniffing on %s...\n", ng.iface)

    // Open device
    handle, err := pcap.OpenLive(ng.iface, int32(ng.snapshotLen), ng.promisc, ng.timeout)
    if err != nil {
        return err
    }
    defer handle.Close()

    // Create writer if outpath is set
    var writer *pcapgo.Writer
    var f *os.File
    if ng.outpath != "" {
        writer, f = ng.writer(handle)
        defer f.Close()
    }

    // Set BPFFilter if present
    if ng.bpf != "" {
        if err := handle.SetBPFFilter(ng.bpf); err != nil {
            return err
        }
    }

    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    for packet := range packetSource.Packets() {
        if !ng.quiet { fmt.Println(packet) }
        if writer != nil { writer.WritePacket(packet.Metadata().CaptureInfo, packet.Data()) }
    }

    return nil
}

// Creates file, writer and writes file header
func (ng *NosyGopher) writer(handle *pcap.Handle) (*pcapgo.Writer, *os.File) {
    f, _ := os.Create(ng.outpath)
    w := pcapgo.NewWriter(f)
    w.WriteFileHeader(uint32(ng.snapshotLen), handle.LinkType())
    return w, f
}

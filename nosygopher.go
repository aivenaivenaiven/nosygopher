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
    iface []string
    outpath, bpf string
    quiet, promisc bool
    snapshotLen int
    timeout time.Duration
}

type NGResult struct {
  err error
  packet gopacket.Packet
  writer pcapgo.Writer
}

func(ng *NosyGopher) Sniff() error {
  var []<-chan string chans
  for _, dev := range ng.iface {
    append(chans, ng.sniffDevice(dev))
  }

  c := fanin(chans...)
  for res := range c {
    if !ng.quiet { fmt.Println(res.packet) }
    if res.writer != nil { res.writer.WritePacket(res.packet.Metadata().CaptureInfo, packet.Data()) }
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
        return NGResult{packet: nil, writer: nil, err: err}
      }
      defer handle.Close()

      // Set BPFFilter if present
      if ng.bpf != "" {
        if err := handle.SetBPFFilter(ng.bpf); err != nil {
          return NGResult{packet: nil, writer: nil, err: err}
        }
      }

      // Create writer if outpath is set
      var writer *pcapgo.Writer
      var f *os.File
      if ng.outpath != "" {
          writer, f = ng.writer(handle)
          defer f.Close()
      }

      packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
      for packet := range packetSource.Packets() {
        c <- NGResult{packet: packet, writer: writer, err: nil}
      }
    }

    return c
}

// Creates file, writer and writes file header
func (ng *NosyGopher) writer(handle *pcap.Handle) (*pcapgo.Writer, *os.File) {
    f, _ := os.Create(ng.outpath)
    w := pcapgo.NewWriter(f)
    w.WriteFileHeader(uint32(ng.snapshotLen), handle.LinkType())
    return w, f
}

// Variadic fanin function
func fanin(inputs ...<-chan string) <-chan string {
  agg := make(chan string)

  _, ch = range inputs {
    go func(c chan string) {
      for msg := range c {
        agg <- msg
      }
    }(ch)
  }
}

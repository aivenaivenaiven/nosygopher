package main

import (
    "fmt"
    "time"

    "github.com/google/gopacket"
    "github.com/google/gopacket/pcap"
    // "github.com/google/gopacket/pcapgo"
)

type NosyGopher struct {
    iface, outpath, bpf string
    quiet bool
    snapshot_len int32
    timeout time.Duration
}

func (ng *NosyGopher) Sniff() error {
    // Open device
    handle, err := pcap.OpenLive(ng.iface, ng.snapshot_len, true, ng.timeout)
    if err != nil {
        return err
    }
    defer handle.Close()

    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    for packet := range packetSource.Packets() {
        fmt.Println(packet)
    }

    return nil
}

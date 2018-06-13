package main

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/google/gopacket/pcap"
	"github.com/urfave/cli"
)

var (
	ifaceList string
	outpath   string
	bpf       string
	re        string
	quiet     bool = false
	promisc   bool = false
)

func main() {
	app := cli.NewApp()
	app.Name = "nosygopher"
	app.Usage = "sniff things"
	app.Version = "0.1.1"

	app.Commands = []cli.Command{
		cli.Command{
			Name:   "list",
			Usage:  "list interfaces nosygopher can sniff",
			Action: listInterfaces,
		},
		cli.Command{
			Name:  "sniff",
			Usage: "print contents of packets on a network interface",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:        "interface, i",
					Value:       "en0",
					Usage:       "comma-separated list of interface devices to sniff on (e.g. en0,bridge0)",
					Destination: &ifaceList,
				},
				cli.StringFlag{
					Name:        "outpath, o",
					Usage:       "path to write pcap file to, if left empty will not write",
					Destination: &outpath,
				},
				cli.StringFlag{
					Name:        "bpf, b",
					Usage:       "berkeley packet filter string ('tcp and port 80')",
					Destination: &bpf,
				},
				cli.StringFlag{
					Name:        "regex, r",
					Usage:       "regular expression to match against data payload of packet",
					Destination: &re,
				},
				cli.BoolFlag{
					Name:        "quiet, q",
					Usage:       "if present will not log to stdout",
					Destination: &quiet,
				},
				cli.BoolFlag{
					Name:        "promiscuous, p",
					Usage:       "capture in promiscuous mode",
					Destination: &promisc,
				},
			},
			Action: sniff,
		},
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

func sniff(c *cli.Context) error {
	ifaces := strings.Split(ifaceList, ",")

	ng := NosyGopher{
		ifaces:      ifaces,
		outpath:     outpath,
		bpf:         bpf,
		re:          re,
		quiet:       quiet,
		promisc:     promisc,
		snapshotLen: 1024,
		timeout:     30 * time.Second,
	}
	err := ng.Sniff()
	if err != nil {
		return fmt.Errorf("nosy gopher has issues: %s", err.Error())
	}
	return nil
}

func listInterfaces(c *cli.Context) error {
	fmt.Println("Here's what nosygopher can sniff...")

	var devices []pcap.Interface
	var err error
	devices, err = pcap.FindAllDevs()
	if err != nil {
		return err
	}
	for i, device := range devices {
		fmt.Printf("%d: %s\n", i+1, device.Name)
	}

	return nil
}

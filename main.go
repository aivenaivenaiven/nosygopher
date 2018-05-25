package main

import (
        "log"
        "os"
        "time"
        "fmt"

        "github.com/urfave/cli"
)

var (
        iface string
        outpath string
        bpf string
        quiet bool = false
        promisc bool = false
)

func main() {
  app := cli.NewApp()
  app.Name = "nosygopher"
  app.Usage = "sniff shit"
  app.Version = "0.0.1"

  app.Flags = []cli.Flag {
    cli.StringFlag{
      Name:        "interface",
      Value:       "en0",
      Usage:       "interface device to sniff on (en0, bridge0)",
      Destination:  &iface,
    },
    cli.StringFlag{
      Name:        "outpath",
      Usage:       "path to write pcap file to, if left empty will not write",
      Destination:  &outpath,
    },
    cli.StringFlag{
      Name:        "bpf",
      Usage:       "berkeley packet filter string ('tcp and port 80')",
      Destination:  &bpf,
    },
    cli.BoolFlag{
      Name:        "quiet",
      Usage:       "if present will not log to stdout",
      Destination:  &quiet,
    },
    cli.BoolFlag{
      Name:        "promiscuous",
      Usage:       "capture in promiscuous mode",
      Destination:  &promisc,
    },
  }

  app.Action = func(c *cli.Context) error {
      ng := NosyGopher{
          iface: iface,
          outpath: outpath,
          bpf: bpf,
          quiet: quiet,
          promisc: promisc,
          snapshotLen: 1024,
          timeout: 30 * time.Second,
      }
      err := ng.Sniff()
      if err != nil {
          return fmt.Errorf("nosy gopher has issues: %s", err.Error())
      }
      return nil
  }

  err := app.Run(os.Args)
  if err != nil {
    log.Fatal(err)
  }
}

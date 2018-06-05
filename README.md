# nosygopher

nosygopher is a Golang command line utility for sniffing those smelly network packets.

## Features
- List network interfaces on the system which nosygopher can capture from with `nosygopher list`
- Capture packets from multiple interface devices concurrently, e.g. `nosygopher sniff -i en0,vboxnet0,ipsec0`

## Installation

```
go get "github.com/aivensong/nosygopher"
```

Make sure your `$GOPATH/bin` is in your `$PATH`.

## Usage

To see a list of all available commands and options, run `nosygopher help`.

```
$ nosygopher help
NAME:
   nosygopher - sniff things

USAGE:
   nosygopher [global options] command [command options] [arguments...]

VERSION:
   0.0.1

COMMANDS:
     list     list interfaces nosygopher can sniff
     sniff    print contents of packets on a network interface
     help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --help, -h     show help
   --version, -v  print the version

$ nosygopher help sniff
NAME:
   nosygopher sniff - print contents of packets on a network interface

USAGE:
   nosygopher sniff [command options] [arguments...]

OPTIONS:
   --interface value, -i value  comma-separated list of interface devices to sniff on (e.g. en0,bridge0) (default: "en0")
   --outpath value, -o value    path to write pcap file to, if left empty will not write
   --bpf value, -b value        berkeley packet filter string ('tcp and port 80')
   --quiet, -q                  if present will not log to stdout
   --promiscuous, -p            capture in promiscuous mode
```

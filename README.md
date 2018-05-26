# nosygopher

nosygopher is a Golang command line utility for sniffing those smelly network packets.

## Installation

```
go get github.com/aivensong/
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
     help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --interface value  interface device to sniff on (en0, bridge0) (default: "en0")
   --outpath value    path to write pcap file to, if left empty will not write
   --bpf value        berkeley packet filter string ('tcp and port 80')
   --quiet            if present will not log to stdout
   --promiscuous      capture in promiscuous mode
   --help, -h         show help
   --version, -v      print the version
```

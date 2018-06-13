# nosygopher

nosygopher is a Golang command line utility for sniffing those smelly network packets. Aims to combine `tcpdump` and `ngrep`-like functionality.


![NG Example](https://user-images.githubusercontent.com/5217789/41317369-fbb74dee-6e62-11e8-9940-90735ea41b3e.gif)

## Features
- List network interfaces on the system which nosygopher can capture from with `nosygopher list`
- Capture packets from multiple interface devices concurrently, e.g. `nosygopher sniff -i en0,vboxnet0,ipsec0`
- Provide a regex to match against packet payloads, e.g. `nosygopher sniff -i en0 -r 'HTTP'`

## Installation

```
go get "github.com/aivensong/nosygopher"
```

Make sure your `$GOPATH/bin` is in your `$PATH`.

## Usage

To see a list of all available commands and options, run `nosygopher help`.

```console
$ nosygopher help
NAME:
   nosygopher - sniff things

USAGE:
   nosygopher [global options] command [command options] [arguments...]

VERSION:
   0.1.1

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
   --regex value, -r value      regular expression to match against data payload of packet
   --quiet, -q                  if present will not log to stdout
   --promiscuous, -p            capture in promiscuous mode
```

## Examples

Concurrently capture packets from `en0` and `lo0` devices, with berkely packet filter string `tcp and port 8080`

```console
$ nosygopher sniff -i en0,lo0 --bpf 'tcp and port 8080'
nosy gopher is sniffing on en0...
nosy gopher is sniffing on lo0...
lo0 -  2018-06-13 11:09:45.998443 -0400 EDT - 88 bytes  ::1:51726 > ::1:8080(http-alt)
lo0 -  2018-06-13 11:09:45.998612 -0400 EDT - 88 bytes  
```

Capture packets from device `en0` that have a payload which matches the regex `"HTTP/[^ ]+ ([\\d]+)"` (an HTTP response), saving the output to a pcap file named `en0_capture.pcap`

```console
$ nosygopher sniff -i en0 -r "HTTP/[^ ]+ ([\\d]+)" -o capture.pcap
en0 -  2018-06-13 11:16:45.916351 -0400 EDT - 211 bytes  ::1:8080(http-alt) > ::1:51769
```

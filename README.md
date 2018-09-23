# Bernard

Bernard is a Rust tool for presence detection in your home network.

It uses a mapping of MAC addresses to labels to accomplish that.
Actually it parses the output of nmap scans, so the nmap tool is required to be installed.

Could be used to setup home automation etc. 

Inspired by [home assistent](https://www.home-assistant.io/getting-started/presence-detection/) and written to learn more about the Rust programming language.

## requirements

* Nmap

## build

```bash
cargo build --release
```

## usage

```txt
Bernard

USAGE:
    bernard [FLAGS] [OPTIONS] --config <config> --network <network>

FLAGS:
    -h, --help       Prints help information
    -q, --quiet      Quiet mode
    -V, --version    Prints version information
    -v, --verbose    Verbose mode (-v, -vv, -vvvvv, etc)

OPTIONS:
    -c, --config <config>          Path to config file
    -o, --output <metrics_path>    Output filepath for metrics file, e.g. /var/www/html/metrics.txt [default:
                                   metrics.txt]
    -n, --network <network>        CIDR notation of the network you want to scan, e.g. 192.168.178.1/24
```

# Bernard

Bernard is a Rust tool for presence detection in your home network.

It uses a mapping of MAC addresses to labels to accomplish that.
Actually it parses the output of nmap scans, so the nmap tool is required to be installed.

Could be used to setup home automation etc. 

Inspired by [home assistent](https://www.home-assistant.io/getting-started/presence-detection/) and written to learn more about the Rust programming language.

## requirements

* [Nmap](https://nmap.org/)

## build

```bash
cargo build --release
```

## get from crates.io

```bash
cargo install bernard
```

## usage

```txt
Bernard

USAGE:
    bernard [FLAGS] [OPTIONS] --config <config> --network <network>

FLAGS:
    -h, --help       Prints help information
    -q, --quiet      Run in quiet mode
    -V, --version    Prints version information
    -v, --verbose    Verbose mode (-v, -vv, -vvvvv, etc)

OPTIONS:
    -c, --config <config>          Path to config file
    -o, --output <metrics_path>    Output filepath for metrics file, e.g. /var/www/html/metrics.txt [default:
                                   metrics.txt]
    -n, --network <network>        CIDR notation of the network you want to scan, e.g. 192.168.178.1/24
```

## run with docker

```bash
docker build -t bernard .
docker run --rm -t --volume /home/your-config.yaml:/opt/bernard/config.yaml --network host bernard -c config.yaml -n 192.168.1.1/24
```

## config example

```yaml
labels:
  some-label:
    - "some-valid-mac"
  other-label:
    - "valid-mac"
    - "another-valid-mac"
```

## output example

```txt

# HELP devices Devices with status
# TYPE devices gauge
devices{hostname="HP60BAG4",mac="00:00:00:00:00:00"} 1
devices{hostname="BUD2AA99",mac="00:00:00:00:00:00"} 1
devices{hostname="OnePlus_3",mac="00:00:00:00:00:00"} 1
devices{hostname="amazon-fdsfds",mac="00:00:00:00:00:00"} 1
devices{hostname="some.device",mac="00:00:00:00:00:00"} 1
devices{hostname="otherother-device",mac=""} 1
devices{hostname="raspberrypi",mac="00:00:00:00:00:00"} 1

# HELP label Label with status
# TYPE label gauge
labels{name="some-label"} 1
labels{name="other-label"} 0
```

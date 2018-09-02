use std::net::IpAddr;
use std::net::Ipv4Addr;
use pnet::datalink;
use std::str::FromStr;
use ipnetwork::Ipv4Network;
use pnet::packet::icmp::echo_request::EchoRequest;
use std::process::Command;


#[macro_use]
use std::vec;

pub struct Scanner {

}

#[derive(Debug)]
pub struct Device {
    ip_address: IpAddr,
    name: String,
    mac: String,
}

impl Scanner {
    fn is_reachable(ip : Ipv4Addr) -> bool {
        let partial_packet: PartialTCPPacketData = PartialTCPPacketData {
            destination_ip: &ip,
            iface_ip,
            iface_name: &interface.name,
            iface_src_mac: &interface.mac.unwrap(),
        };

        let (mut tx, _) = match pnet_datalink::channel(&interface, Default::default()) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => panic!("Unknown channel type"),
            Err(e) => panic!("Error happened {}", e),
        };
    }


    pub fn scan_devices(gateway : &str) -> Vec<Device> {
        println!("{}", gateway);
        // scan devices over all interfaces
        for interface in datalink::interfaces().iter() {
            println!("Available interfaces: {:?}", interface);
            let ipv4_address = match interface.ips[0].ip() {
                IpAddr::V4(ip) => ip,
                _ => panic!("Invalid address"),
            };

            let network = match Ipv4Network::new(ipv4_address, interface.ips[0].prefix()) {
                Ok(T) => T,
                Err(E) => panic!("Error, while getting network addresses"),
            };

            for address in network.iter() {
                is_reachable(&address);
                println!("{:?}", &address);
            }
        }

        let test_device = Device {
            ip_address: IpAddr::V4(Ipv4Addr::new(192, 168, 178, 22)),
            name: String::from("Test"),
            mac: String::from("RandomMAC"),
        };

        vec!(test_device)
    }
}
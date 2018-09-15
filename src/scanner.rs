use std::net::IpAddr;
use std::net::Ipv4Addr;
use pnet::datalink;
use std::str::FromStr;
use ipnetwork::Ipv4Network;
use pnet::packet::icmp::echo_request::EchoRequest;
use std::process::Command;
use tempfile::NamedTempFile;
use std::io::Read;

#[macro_use]
use std::vec;
use std::io::BufReader;
use xml::reader::{EventReader, XmlEvent};

pub struct Scanner {

}

#[derive(Debug)]
pub struct Device {
    ip_address: IpAddr,
    name: String,
    mac: String,
    owner: String,
    online: bool,
}

#[derive(Debug, Clone)]
struct Host {
    ip: String,
    hostname: String,
    mac: String,
}

impl Host {
    pub fn new() -> Host {
        Host {
            ip: String::new(),
            hostname: String::new(),
            mac: String::new(),
        }
    }

    pub fn set_ip(&mut self, ip: String) {
        self.ip = ip;
    }

    pub fn set_hostname(&mut self, hostname: String) {
        self.hostname = hostname;
    }

    pub fn set_mac(&mut self, mac: String) {
        self.mac = mac;
    }
}

impl Scanner {
    fn people_online(mac_address: &str)  {
        // scan all devices from people that are contained in xml
    }

    pub fn parse_nmap_xml(&self) {
        let mut file = NamedTempFile::new().unwrap();
        let path = file.path().to_str().clone().unwrap().to_string();
        let result = Command::new("nmap")
            //.arg("-sL")
            .arg("-sT")
            .arg("--disable-arp-ping")
            .arg("-v")
            .arg("192.168.178.*")
            .arg("-oX")
            .arg(path)
            .output().unwrap();
        if false {
            let mut s = String::new();
            file.read_to_string(&mut s).unwrap();
            println!("{}", s);
            return;
        }

        let mut buf_reader = BufReader::new(file.as_file());
        let xml_reader = EventReader::new(buf_reader);

        let mut hosts: Vec<Host> = vec!();
        let mut current_host: Option<Host> = None;
        let mut is_online: bool = false;
        for entry in xml_reader {
            match entry {
                Ok(XmlEvent::StartElement { name, attributes, .. }) => {
                    if name.local_name.eq("host") {
                        //println!("Start{:?}", attributes);
                        current_host = Some(Host::new());
                    }
                    let host = match &mut current_host {
                        Some(x) => x,
                        None => continue,
                    };
                    if name.local_name.eq("status") {
                        for attr in &attributes {
                            if attr.name.local_name.eq("state") {
                                if attr.value.eq("up") {
                                    is_online = true;
                                }
                            }
                        }
                    }
                    if name.local_name.eq("address") {
                        let mut addr_type: Option<String> = None;
                        let mut addr: Option<String> = None;
                        for attr in &attributes {
                            if attr.name.local_name.eq("addr") {
                                addr = Some(attr.value.clone());
                            }
                            if attr.name.local_name.eq("addrtype") {
                                addr_type = Some(attr.value.clone());
                            }
                        }

                        match addr_type {
                            Some(ref x) if x.eq("mac") => host.set_mac(addr.unwrap()),
                            Some(ref x) if x.eq("ipv4") => host.set_ip(addr.unwrap()),
                            _ => (),
                        }
                    }
                    if name.local_name.eq("hostname") {
                        for attr in attributes {
                            if attr.name.local_name.eq("name") {
                                host.set_hostname(attr.value.clone());
                            }
                        }
                    }
                    continue
                }
                Ok(XmlEvent::EndElement { name }) => {
                    if name.local_name.eq("host") {
                        let host = match &current_host {
                            Some(x) => x,
                            None => panic!("Invalid xml!"),
                        };
                        if is_online {
                            hosts.push(current_host.clone().unwrap());
                        }
                        is_online = false;
                    }
                    //current_host
                    //println!("End{}-{}", depth, name);
                    continue
                }
                Err(e) => {
                    println!("Error: {}", e);
                    break;
                }
                _ => {}

            }
        }
        println!("{:?}", hosts);
    }

    pub fn new() -> Scanner {
        Scanner{}
    }

    pub fn scan_devices(&self, gateway : &str) -> Vec<Device> {
        println!("{}", gateway);
        self.parse_nmap_xml();
        /*
        // scan devices over all interfaces
        for interface in datalink::interfaces().iter() {
            //println!("Available interfaces: {:?}", interface);
            let ipv4_address = match interface.ips[0].ip() {
                IpAddr::V4(ip) => ip,
                _ => panic!("Invalid address"),
            };

            let network = match Ipv4Network::new(ipv4_address, interface.ips[0].prefix()) {
                Ok(T) => T,
                Err(_) => panic!("Error, while getting network addresses"),
            };

            for address in network.iter() {
                // is_reachable(&address);
                // println!("{:?}", &address);
            }
        }
*/
        let test_device = Device {
            ip_address: IpAddr::V4(Ipv4Addr::new(192, 168, 178, 22)),
            name: String::from("Test"),
            mac: String::from("RandomMAC"),
            owner: String::from("Test"),
            online: false,
        };

        vec!(test_device)
    }
}
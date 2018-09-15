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
    status: String,
    address: String,
    hostname: String,
}

impl Host {
    pub fn new() -> Host {
        Host {
            status: String::new(),
            address: String::new(),
            hostname: String::new(),
        }
    }

    pub fn set_status(&mut self, status: String) {
        self.status = status
    }

    pub fn set_address(&mut self, address: String) {
        self.address = address
    }

    pub fn set_hostname(&mut self, hostname: String) {
        self.hostname = hostname
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
            .arg("-sL")
            .arg("192.168.178.*")
            .arg("-oX")
            .arg(path)
            .output().unwrap();
        let mut buf_reader = BufReader::new(file.as_file());
        let xml_reader = EventReader::new(buf_reader);

        let mut depth = 0;
        let mut hosts: Vec<Host> = vec!();
        let mut current_host: Option<Host> = None;
        for entry in xml_reader {
            match entry {
                Ok(XmlEvent::StartElement { name, attributes, .. }) => {
                    if name.local_name.eq("host") {
                        //println!("Start{:?}", attributes);
                        current_host = Some(Host::new());
                    }
                    let host = match &mut current_host {
                        Some(x) => x,
                        None => panic!("Invalid xml!"),
                        _ => panic!("Invalid xml!"),
                    };
                    if name.local_name.eq("status") {
                        //println!("Start{:?}", attributes);
                        for attr in attributes {
                            if attr.name.local_name.eq("state") {
                                host.set_status(attr.value);
                            }
                        }
                    }
                    if name.local_name.eq("address") {
                        for attr in attributes {
                            if attr.name.local_name.eq("addr") {
                                host.set_address(attr.value);
                            }
                        }
                    }
                    if name.local_name.eq("hostnames") {
                        for attr in attributes {
                            if attr.name.local_name.eq("addr") {
                                host.set_address(attr.value);
                            }
                        }
                    }
                    depth += 1;
                    continue
                }
                Ok(XmlEvent::EndElement { name }) => {
                    depth -= 1;
                    if name.local_name.eq("host") {
                        let host = match &current_host {
                            Some(x) => x,
                            None => panic!("Invalid xml!"),
                        };
                        println!("{}", host.status);
                        if host.status.eq("up") {
                            hosts.push(current_host.clone().unwrap());
                        }
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
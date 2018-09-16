use HashMap;
use ipnetwork::Ipv4Network;
use pnet::datalink;
use std::io::BufReader;
use std::io::Read;
use std::net::IpAddr;
use std::process::Command;
use std::vec;
use std::fmt;
use tempfile::NamedTempFile;
use xml::reader::{EventReader, XmlEvent};

pub struct Scanner {}

#[derive(Debug, Clone)]
struct Device {
    ip: String,
    hostname: String,
    mac: String,
}

impl Device {
    pub fn new() -> Device {
        Device {
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
    fn get_devices(&self, cidr: &str) -> Vec<Device> {
        let file = NamedTempFile::new().unwrap();
        let path = file.path().to_str().clone().unwrap().to_string();
        Command::new("nmap")
            .arg("-sn")
            .arg("192.168.178.28/24")
            .arg("-oX")
            .arg(path)
        .output().expect("Error, while running nmap");

        let buf_reader = BufReader::new(file.as_file());
        let xml_reader = EventReader::new(buf_reader);

        let mut hosts: Vec<Device> = vec!();
        let mut current_host: Option<Device> = None;
        let mut is_online: bool = false;
        for entry in xml_reader {
            match entry {
                Ok(XmlEvent::StartElement { name, attributes, .. }) => {
                    if name.local_name.eq("host") {
                        //println!("Start{:?}", attributes);
                        current_host = Some(Device::new());
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
                        if is_online {
                            hosts.push(current_host.clone().unwrap());
                        }
                        is_online = false;
                    }
                    continue
                }
                Err(e) => {
                    println!("Error: {}", e);
                    break;
                }
                _ => {}

            }
        }
        hosts
    }

    pub fn new() -> Scanner {
        Scanner{}
    }

    fn get_interfaces(&self) -> Vec<Ipv4Network> {
        let mut interfaces: Vec<Ipv4Network> = vec!();
        for interface in datalink::interfaces() {
            //println!("Available interfaces: {:?}", interface);
            let ipv4_address = match interface.ips[0].ip() {
                IpAddr::V4(ip) => ip,
                _ => continue,
            };
            let network = match Ipv4Network::new(ipv4_address, interface.ips[0].prefix()) {
                Ok(x) => x,
                Err(_) => continue,
            };
            interfaces.push(network);
        }
        interfaces
    }

    pub fn get_people_online(&self, people_map: &HashMap<String, Vec<String>>) -> Vec<String> {
        let mut people_online: Vec<String> = vec!();
        let interfaces: Vec<Ipv4Network> = self.get_interfaces();
        for iface in interfaces {
            info!("Scanning over interface {:?}", iface);
            let online_devices = self.get_devices(format!("{}/{}", iface.network(), iface.prefix()).as_str());
            let online_macs: Vec<String> = online_devices.iter().map(|x| x.mac.clone()).collect();
            for person in people_map {
                for mac in person.1 {
                    let mac = mac.to_ascii_uppercase();
                    if online_macs.contains(&mac) {
                        if !people_online.contains(person.0) {
                            people_online.push(person.0.clone());
                        }
                        break;
                    }
                }
            }
        }
        people_online
    }
}

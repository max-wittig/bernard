use std::collections::HashMap;
use std::io::BufReader;
use std::process::Command;
use std::net::Ipv4Addr;

use tempfile::NamedTempFile;
use xml::reader::{EventReader, XmlEvent};

pub struct Scanner {
    cidr: String,
}

#[derive(Debug, Clone)]
pub struct Device {
    pub ip: Option<Ipv4Addr>,
    pub hostname: String,
    pub mac: String,
    pub owner: String,
}

impl Device {
    pub fn new() -> Device {
        Device {
            ip: None,
            hostname: String::new(),
            mac: String::new(),
            owner: String::new(),
        }
    }

    pub fn set_ip(&mut self, ip: Option<Ipv4Addr>) {
        self.ip = ip
    }

    pub fn set_hostname(&mut self, hostname: String) {
        self.hostname = hostname;
    }

    pub fn set_mac(&mut self, mac: String) {
        self.mac = mac;
    }

    pub fn set_owner(&mut self, owner: String) {
        self.owner = owner;
    }
}

impl Scanner {
    fn get_devices(&self) -> Vec<Device> {
        let file = NamedTempFile::new().unwrap();
        let path = file.path().to_str().unwrap().to_string();
        Command::new("nmap")
            .arg("-sn")
            .arg("-PS")
            .arg(self.cidr.as_str())
            .arg("-oX")
            .arg(path)
            .output()
            .expect("Error, while running nmap");

        let buf_reader = BufReader::new(file.as_file());
        let xml_reader = EventReader::new(buf_reader);

        let mut hosts: Vec<Device> = vec![];
        let mut current_host: Option<Device> = None;
        let mut is_online: bool = false;
        for entry in xml_reader {
            match entry {
                Ok(XmlEvent::StartElement {
                    name, attributes, ..
                }) => {
                    if name.local_name.eq("host") {
                        current_host = Some(Device::new());
                        debug!("Found new host");
                    }
                    let host = match &mut current_host {
                        Some(x) => x,
                        None => continue,
                    };
                    if name.local_name.eq("status") {
                        for attr in &attributes {
                            if attr.name.local_name.eq("state") && attr.value.eq("up") {
                                is_online = true;
                                debug!("Host is online")
                            }
                        }
                    }
                    if name.local_name.eq("address") {
                        let mut addr_type: Option<String> = None;
                        let mut addr: Option<String> = None;
                        let mut ip_addr: Option<Ipv4Addr> = None;
                        let mut mac_addr: Option<String> = None;
                        for attr in &attributes {
                            if attr.name.local_name.eq("addr") {
                                addr = Some(attr.value.clone());
                            } else if attr.name.local_name.eq("addrtype") {
                                addr_type = Some(attr.value.clone());
                            }
                        }

                        match addr_type {
                            Some(ref x) if x.eq("mac") => host.set_mac(addr.unwrap()),
                            Some(ref x) if x.eq("ipv4") => {
                                // check if address is really an Ipv4Addr
                                ip_addr = match x.clone().parse() {
                                    Ok(a) => Some(a),
                                    Err(_) => None, //TODO: throw xml error
                                };
                                host.set_ip(ip_addr)
                            },
                            _ => (),
                        }
                        debug!("Found address for host");
                    }
                    if name.local_name.eq("hostname") {
                        for attr in attributes {
                            if attr.name.local_name.eq("name") {
                                host.set_hostname(attr.value.clone());
                                debug!("Hostname set!");
                                break;
                            }
                        }
                    }
                    continue;
                }
                Ok(XmlEvent::EndElement { name }) => {
                    if name.local_name.eq("host") {
                        if is_online {
                            hosts.push(current_host.clone().unwrap());
                        }
                        is_online = false;
                    }
                    continue;
                }
                Err(e) => {
                    panic!("Error, while parsing xml: {}", e);
                }
                _ => {}
            }
        }
        hosts
    }

    pub fn new(cidr: &str) -> Scanner {
        Scanner {
            cidr: cidr.to_string(),
        }
    }

    pub fn get_people_online(&self, people_map: &HashMap<String, Vec<String>>) -> Vec<Device> {
        let mut online_devices = self.get_devices();
        for person in people_map {
            for mac in person.1 {
                let mac = mac.to_ascii_uppercase();
                for device in online_devices.iter_mut() {
                    if mac.eq(&device.mac.to_ascii_uppercase()) {
                        // found device, assign owner
                        device.set_owner(person.0.clone());
                        info!("Setting owner for device {} to {}", &device.mac, person.0);
                    }
                }
            }
        }
        online_devices
    }
}

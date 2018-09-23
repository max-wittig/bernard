use std;
use std::collections::HashMap;
use std::io::BufReader;
use std::process::exit;
use std::process::{Command, Stdio};
use ExitCodes;

use tempfile::NamedTempFile;
use xml::reader::{EventReader, XmlEvent};

pub struct Scanner {
    cidr: String,
}

#[derive(Debug, Clone)]
pub struct Device {
    pub ip: String,
    pub hostname: String,
    pub mac: String,
    pub owner: String,
}

impl Device {
    pub fn new() -> Device {
        Device {
            ip: String::new(),
            hostname: String::new(),
            mac: String::new(),
            owner: String::new(),
        }
    }

    pub fn set_ip(&mut self, ip: String) {
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
        match Command::new("nmap")
            .arg("-sn")
            .arg("-PS")
            .arg(self.cidr.as_str())
            .arg("-oX")
            .arg(path)
            .stdout(Stdio::null())
            .output()
        {
            Ok(r) => r,
            Err(ref e) if e.kind() == std::io::ErrorKind::NotFound => {
                error!("Nmap is not installed!");
                exit(ExitCodes::NmapNotInstalled as i32);
            }
            Err(_) => {
                error!("Error, while running Nmap!");
                exit(ExitCodes::NmapRunError as i32);
            }
        };

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
                                debug!("Host is online");
                            }
                        }
                    }
                    if name.local_name.eq("address") {
                        let mut addr_type: Option<String> = None;
                        let mut addr: Option<String> = None;
                        for attr in &attributes {
                            if attr.name.local_name.eq("addr") {
                                addr = Some(attr.value.clone());
                            } else if attr.name.local_name.eq("addrtype") {
                                addr_type = Some(attr.value.clone());
                            }
                        }

                        match addr_type {
                            Some(ref x) if x.eq("mac") => host.set_mac(addr.unwrap()),
                            Some(ref x) if x.eq("ipv4") => host.set_ip(addr.unwrap()),
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

    pub fn get_labels_online(&self, label_map: &HashMap<String, Vec<String>>) -> Vec<Device> {
        let mut online_devices = self.get_devices();
        for person in label_map {
            for mac in person.1 {
                let mac = mac.to_ascii_uppercase();
                for device in &mut online_devices {
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

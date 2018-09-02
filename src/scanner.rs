use std::net::IpAddr;
use std::net::Ipv4Addr;

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
    pub fn scan_devices(gateway : &str) -> Vec<Device> {
        println!("{}", gateway);
        let test_device = Device {
            ip_address: IpAddr::V4(Ipv4Addr::new(192, 168, 178, 22)),
            name: String::from("Test"),
            mac: String::from("RandomMAC"),
        };
        vec!(test_device)
    }
}
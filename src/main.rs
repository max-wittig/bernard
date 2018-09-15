mod scanner;
extern crate pnet;
extern crate ipnetwork;

#[macro_use]
extern crate serde_derive;
extern crate serde_yaml;
extern crate xml;
extern crate tempfile;

use scanner::Scanner;
use std::collections::HashMap;
use std::fs::File;
use std::io::Read;


#[derive(Debug, Serialize, Deserialize)] // sudo
struct Config {
    people: HashMap<String, Vec<String>>,
}

fn get_config(filename: &str) -> Config {
    let mut file = File::open(&filename).unwrap();
    let mut file_content = String::new();
    &file.read_to_string(&mut file_content);
    serde_yaml::from_str(&file_content).unwrap()
}

fn main() {
    let config = get_config("config.yaml");
    println!("{:?}", config);
    let gateway = String::from("192.168.178.1");
    let scanner = Scanner::new();
    scanner.parse_nmap_xml()
    //Scanner::scan_devices(gateway.as_str());
    // println!("{:?}", &addresses)
}

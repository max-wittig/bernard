extern crate ipnetwork;
extern crate pnet;
#[macro_use]
extern crate serde_derive;
extern crate serde_yaml;
extern crate tempfile;
extern crate xml;
#[macro_use]
extern crate log;
#[macro_use]
extern crate prometheus;
use std::io::prelude::*;

use prometheus::{Opts, Registry, Gauge, GaugeVec, TextEncoder, Encoder};
use scanner::Scanner;
use std::collections::HashMap;
use std::fmt;
use std::fs::File;
use std::io;
use std::io::Read;

mod scanner;


#[derive(Debug, Serialize, Deserialize)]
enum ConfigError {
    ReadError,
}

impl From<std::io::Error> for ConfigError {
    fn from(_: std::io::Error) -> ConfigError {
        ConfigError::ReadError
    }
}

impl From<serde_yaml::Error> for ConfigError {
    fn from(_: serde_yaml::Error) -> ConfigError {
        ConfigError::ReadError
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Config {
    people: HashMap<String, Vec<String>>,
}

fn get_config(filename: &str) -> Result<Config, ConfigError> {
    let mut file = File::open(&filename)?;
    let mut file_content = String::new();
    file.read_to_string(&mut file_content)?;
    Ok(serde_yaml::from_str(&file_content)?)
}

fn main() {
    let config = match get_config("config.yaml") {
        Ok(x) => x,
        Err(_) => panic!("Could not read config!"),
    };

    info!("Config loaded");
    let scanner = Scanner::new();
    let people_online = scanner.get_people_online(&config.people);
    println!("Online are: {}", people_online.join(", "));
    //let people_online = vec!("max".to_string(), "nadia".to_string());
    let mut people_status_map : HashMap<String, f64> = HashMap::new();
    for person in config.people {
        if people_online.contains(&person.0) {
            people_status_map.insert(person.0.clone(), 1.0);
        } else {
            people_status_map.insert(person.0.clone(), 0.0);
        }
    }
    generate_node_export(&people_status_map);
}

fn generate_node_export(people: &HashMap<String, f64>) {
    let r = Registry::new();
    let mut gauge_vec_opts = Opts::new("people", "People online status");

    let gauge_vec: GaugeVec = GaugeVec::new(gauge_vec_opts, &["name"]).unwrap();
    r.register(Box::new(gauge_vec.clone())).unwrap();
    for person in people {
        gauge_vec.with_label_values(&[person.0.as_str()]).set(*person.1);
    }

    // Gather the metrics.
    let mut buffer = vec![];
    let encoder = TextEncoder::new();
    let metric_families = r.gather();
    encoder.encode(&metric_families, &mut buffer).unwrap();

    // Output to the standard output.
    println!("{}", String::from_utf8(buffer.clone()).unwrap());
    let mut out_file = File::create("metrics.txt").unwrap();
    out_file.write_all(String::from_utf8(buffer).unwrap().as_bytes()).unwrap();
}

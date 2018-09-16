#[macro_use]
extern crate log;
extern crate prometheus;
#[macro_use]
extern crate serde_derive;
extern crate serde_yaml;
extern crate stderrlog;
#[macro_use]
extern crate structopt;
extern crate tempfile;
extern crate xml;

use prometheus::{Encoder, GaugeVec, Opts, Registry, TextEncoder};
use scanner::Scanner;
use std::collections::HashMap;
use std::fmt;
use std::fmt::Display;
use std::fs::File;
use std::io::prelude::*;
use std::io::Read;
use structopt::StructOpt;

mod scanner;

#[derive(Debug, Serialize, Deserialize)]
enum ConfigError {
    ReadError,
}

impl Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self)
    }
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

/// Network-scanner
#[derive(StructOpt, Debug)]
#[structopt()]
struct Opt {
    #[structopt(short = "q", long = "quiet")]
    quiet: bool,
    /// Verbose mode (-v, -vv, -vvv, etc)
    #[structopt(short = "v", long = "verbose", parse(from_occurrences))]
    verbose: usize,
    /// Timestamp (sec, ms, ns, none)
    #[structopt(short = "t", long = "timestamp")]
    ts: Option<stderrlog::Timestamp>,
    /// Path to config file
    #[structopt(short = "c", long = "config")]
    config: String,
    /// IP in CIDR notation of the network you want to scan, e.g. 192.168.178.28/24
    #[structopt(short = "n", long = "network")]
    network: String,
}

fn main() {
    let opt = Opt::from_args();
    stderrlog::new()
        .module(module_path!())
        .quiet(opt.quiet)
        .verbosity(opt.verbose)
        .timestamp(opt.ts.unwrap_or(stderrlog::Timestamp::Off))
        .init()
        .unwrap();

    let config = get_config(&opt.config).expect("Could not read config file!");
    info!("Config loaded");
    let scanner = Scanner::new(&opt.network);
    info!("Running nmap to detect devices...");
    let people_online = scanner.get_people_online(&config.people);
    info!("Online: {}", people_online.join(", "));
    //let people_online = vec!("max".to_string(), "nadia".to_string());
    let mut people_status_map: HashMap<String, f64> = HashMap::new();
    for person in config.people {
        if people_online.contains(&person.0) {
            people_status_map.insert(person.0.clone(), 1.0);
        } else {
            people_status_map.insert(person.0.clone(), 0.0);
        }
    }
    write_metrics_file(&people_status_map);
}

fn write_metrics_file(people: &HashMap<String, f64>) {
    let r = Registry::new();
    let gauge_vec_opts = Opts::new("people", "People online status");

    let gauge_vec: GaugeVec = GaugeVec::new(gauge_vec_opts, &["name"]).unwrap();
    r.register(Box::new(gauge_vec.clone())).unwrap();
    for person in people {
        gauge_vec
            .with_label_values(&[person.0.as_str()])
            .set(*person.1);
    }

    // Gather the metrics.
    let mut buffer = vec![];
    let encoder = TextEncoder::new();
    let metric_families = r.gather();
    encoder.encode(&metric_families, &mut buffer).unwrap();
    info!("Exporter file: {}", String::from_utf8(buffer.clone()).unwrap());
    let mut out_file = File::create("metrics.txt").unwrap();
    out_file
        .write_all(String::from_utf8(buffer).unwrap().as_bytes())
        .expect("Could not write output file!");
}

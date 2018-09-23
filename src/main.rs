#[macro_use]
extern crate log;
extern crate prometheus;
#[macro_use]
extern crate serde_derive;
extern crate serde_yaml;
#[macro_use]
extern crate structopt;
extern crate eui48;
extern crate simplelog;
extern crate tempfile;
extern crate xml;

use eui48::MacAddress;
use prometheus::{Encoder, GaugeVec, Opts, Registry, TextEncoder};
use scanner::Scanner;
use simplelog::{CombinedLogger, LevelFilter, TermLogger};
use std::collections::HashMap;
use std::env;
use std::fmt;
use std::fmt::Display;
use std::fs::File;
use std::io::prelude::*;
use std::io::Read;
use std::process::exit;
use structopt::StructOpt;

mod scanner;

#[derive(Debug, Serialize, Deserialize)]
enum ConfigError {
    ReadError,
    ParseError,
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

enum ExitCodes {
    RootRequired = 1,
    ConfigFileDoesNotExist = 2,
    ConfigInvalid = 3,
    NmapNotInstalled = 4,
    NmapRunError = 5,
    ResultWriteError = 6,
}

#[derive(Debug, Serialize, Deserialize)]
struct Config {
    labels: HashMap<String, Vec<String>>,
}

impl Config {
    fn is_valid(&self) -> bool {
        // check if mac addresses are valid
        for label in &self.labels {
            for address in label.1 {
                match MacAddress::parse_str(address.as_str()) {
                    Ok(r) => r,
                    Err(_) => return false,
                };
            }
        }
        true
    }
}

fn get_config(filename: &str) -> Result<Config, ConfigError> {
    let mut file = File::open(&filename)?;
    let mut file_content = String::new();
    file.read_to_string(&mut file_content)?;
    let config: Config = serde_yaml::from_str(&file_content)?;
    if config.is_valid() {
        Ok(config)
    } else {
        Err(ConfigError::ParseError)
    }
}

/// Bernard
#[derive(StructOpt, Debug)]
#[structopt()]
struct Opt {
    /// Run in quiet mode
    #[structopt(short = "q", long = "quiet")]
    quiet: bool,
    /// Verbose mode (-v, -vv, -vvvvv, etc)
    #[structopt(short = "v", long = "verbose", parse(from_occurrences))]
    verbose: usize,
    /// Path to config file
    #[structopt(short = "c", long = "config")]
    config: String,
    /// CIDR notation of the network you want to scan, e.g. 192.168.178.1/24
    #[structopt(short = "n", long = "network")]
    network: String,
    /// Output filepath for metrics file, e.g. /var/www/html/metrics.txt
    #[structopt(short = "o", long = "output", default_value = "metrics.txt")]
    metrics_path: String,
}

fn is_root() -> bool {
    match env::var("USER") {
        Ok(ref val) if val.eq("root") => true,
        Ok(_) => false,
        Err(_) => false,
    }
}

fn main() {
    let opt = Opt::from_args();
    let mut log_level = match &opt.verbose {
        1 => LevelFilter::Warn,
        2 => LevelFilter::Info,
        3 => LevelFilter::Debug,
        4 => LevelFilter::Trace,
        &r if r > 4 as usize => LevelFilter::Trace,
        _ => LevelFilter::Error,
    };
    if opt.quiet {
        log_level = LevelFilter::Off
    }

    CombinedLogger::init(vec![
        TermLogger::new(log_level, simplelog::Config::default()).unwrap(),
    ]).unwrap();

    if !is_root() {
        error!("This program needs to be run as root!");
        exit(ExitCodes::RootRequired as i32);
    }

    let config = match get_config(&opt.config) {
        Ok(r) => r,
        Err(ConfigError::ParseError) => {
            error!("Config is invalid. Please make sure that only valid MAC addresses are used!");
            exit(ExitCodes::ConfigInvalid as i32);
        }
        Err(ConfigError::ReadError) => {
            error!("Config file does not exist at the given location!");
            exit(ExitCodes::ConfigFileDoesNotExist as i32);
        }
    };

    info!("Config loaded");
    let scanner = Scanner::new(&opt.network);
    info!("Running nmap to detect devices...");
    let devices_online = scanner.get_labels_online(&config.labels);
    let label_online: Vec<String> = devices_online
        .iter()
        .map(|d| d.owner.clone())
        .filter(|o| !o.is_empty())
        .collect();
    info!("Online: {}", label_online.join(", "));
    let mut label_status_hashmap: HashMap<String, f64> = HashMap::new();
    for label in config.labels {
        if label_online.contains(&label.0) {
            label_status_hashmap.insert(label.0.clone(), 1.0);
        } else {
            label_status_hashmap.insert(label.0.clone(), 0.0);
        }
    }
    write_metrics_file(&label_status_hashmap, &devices_online, &opt.metrics_path);
}

fn write_metrics_file(
    labels: &HashMap<String, f64>,
    devices: &[scanner::Device],
    metrics_path: &str,
) {
    let r = Registry::new();
    let label_gauge_vec_opts = Opts::new("labels", "Label with status");
    let devices_gauge_vec_opts = Opts::new("devices", "Devices with status");

    let label_gauge_vec: GaugeVec = GaugeVec::new(label_gauge_vec_opts, &["name"]).unwrap();
    let devices_gauge_vec: GaugeVec =
        GaugeVec::new(devices_gauge_vec_opts, &["hostname", "mac"]).unwrap();
    r.register(Box::new(label_gauge_vec.clone())).unwrap();
    r.register(Box::new(devices_gauge_vec.clone())).unwrap();
    for label in labels {
        label_gauge_vec
            .with_label_values(&[label.0.as_str()])
            .set(*label.1);
    }

    for device in devices {
        devices_gauge_vec
            .with_label_values(&[device.hostname.as_str(), device.mac.as_str()])
            .set(1.0); // all devices found must be online
    }

    let mut buffer = vec![];
    let encoder = TextEncoder::new();
    let metric_families = r.gather();
    encoder.encode(&metric_families, &mut buffer).unwrap();
    debug!(
        "Exporter file: {}",
        String::from_utf8(buffer.clone()).unwrap()
    );
    let mut out_file = match File::create(metrics_path) {
        Ok(r) => r,
        Err(_) => {
            error!("Could not write results file!");
            exit(ExitCodes::ResultWriteError as i32);
        }
    };

    out_file
        .write_all(String::from_utf8(buffer).unwrap().as_bytes())
        .expect("Could not write output file!");
    info!("Wrote metrics to {}", metrics_path);
}

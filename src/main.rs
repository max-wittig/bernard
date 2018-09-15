extern crate ipnetwork;
extern crate pnet;
#[macro_use]
extern crate serde_derive;
extern crate serde_yaml;
extern crate tempfile;
extern crate xml;

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

    let scanner = Scanner::new();
    scanner.get_people_online(&config.people);
}

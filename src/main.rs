mod scanner;
use scanner::Scanner;

fn main() {
    println!("Hello, world!");
    let gateway = String::from("192.168.178.1");
    let addresses = Scanner::scan_devices(gateway.as_str());
    println!("{:?}", &addresses)
}

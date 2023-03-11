/* client program */
extern crate serde;
use std::{os::unix::net::UnixStream, io::{Write, Read}};
use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    action_type: ActionType
}

#[derive(clap::Subcommand, Debug, serde::Serialize)]
pub enum ActionType {

    /// Insert a new rule to the specified chain
    Insert {

        /// L4 protcol
        #[arg(value_enum, short, required = false, default_value_t = L4prot::Any)]
        l4protocol: L4prot,

        /// L4 source port
        #[arg(short, required = false, default_value_t = 0, requires = "l4protocol")] // a port cannot be specified without the transport layer type
        src_port: u16,

        /// L4 destination port
        #[arg(short, required = false, default_value_t = 0, requires = "l4protocol")]
        dst_port: u16,

        /// action if match occures
        #[arg(required = true)]
        action: Verdict,

        /// source IPv4 address
        #[arg(value_parser = address_parser)]
        src_addr: u32,

        /// source address mask
        #[arg(required = true, value_parser = mask_parser)]
        src_mask: u32,

        /// destination IPv4 address
        #[arg(value_parser = address_parser)]
        dst_addr: u32,

        /// destination address mask
        #[arg(required = true, value_parser = mask_parser)]
        dst_mask: u32,
    },

    /// Delete a rule from specified chain
    Delete,

    /// List rules from a specified chain or all if no chain is specified
    List
}

#[derive(clap::ValueEnum, Debug, Clone, serde::Serialize)]
pub enum L4prot {
    TCP,
    UDP,
    Any
}

#[derive(clap::ValueEnum, Debug, Clone, serde::Serialize)]
pub enum Verdict {
    Accept,
    Drop,
}

// takes number of bits - n - and returns binary form of an address mask with n bits
fn mask_parser(input: &str) -> Result<u32, String> {
    return match input.parse::<u32>() {
        Ok(n) => {
            // enforce max mask value
            if n > 32 {
                return Err(String::from("The mask has too many bits."));
            }
            Ok(u32::MAX >> (32 - n)) // this evaluates to 32 bit unsigned integer with n rightmost bits being 1s
        },
        Err(_) => Err(String::from("The mask is not a valid number."))
    }
}


// transforms a string representation of IPv4 address to the binary form
fn address_parser(input: &str) -> Result<u32, String> {
    // we must have exactly four bytes
    if input.split(".").count() != 4 {
        return Err(String::from("The address does not have exactly four parts. (delimited by .)"));
    }

    // the bytes are moved to an array
    let mut idx = 0;
    let mut address: [u8; 4] = [0; 4];
    let split = input.split(".");

    for byte in split {
        // by parsing to byte, we implicitly enforce value limit 0 - 255
        match byte.parse::<u8>() {
            Ok(n) => {
                address[3-idx] = n;
                idx += 1;
            },
            Err(_) => return Err(String::from("Part of the address is not a number between 0 and 255."))
        }
    }
    // the array is converted to the binary representation of the address
    return Ok(u32::from_le_bytes(address));
}


fn send_to_daemon(message: shared::Msg) -> Result<(), String> {
    // connect to daemon socket
    let mut stream = match UnixStream::connect("/tmp/fw.sock") {
        Ok(it) => it,
        Err(_err) => {
            println!("{}",_err);
            return Err(String::from("Could not connect to the socket"));}
    };

    // serialize the new rule and send through the socket
    let v = serde_json::to_value(message).unwrap().to_string() + "\n";
    match stream.write_all(&v.into_bytes()) {
        Ok(it) => it,
        Err(_err) => return Err(String::from("Could not write to the socket")),
    };

    // receive response from daemon
    let mut response = String::new();
    match stream.read_to_string(&mut response) {
        Ok(_) => {
            println!("{}", response);
        },
        Err(e) => {
            println!("Failed to receive data: {}", e);
        }
    }
    Ok(())
}

fn main() {
    let args = Args::parse();
    // interpret supplied arguments
    match &args.action_type {
        // insert
        ActionType::Insert { l4protocol, src_port, dst_port, action, src_addr, src_mask, dst_addr, dst_mask } => {
            let l4: shared::L4protocols;
            match l4protocol {
                L4prot::TCP => l4 = shared::L4protocols::TCP,
                L4prot::UDP => l4 = shared::L4protocols::UDP,
                _ => l4 = shared::L4protocols::Unknown
            }
            let verdict: bool;
            match action {
                Verdict::Accept => verdict = true,
                Verdict::Drop => verdict = false
            }
            let rule = shared::Rule::new(verdict, shared::IPversions::IPv4, src_addr.clone(), dst_addr.clone(), src_mask.clone(), dst_mask.clone(), l4, src_port.clone(), dst_port.clone());
            let msg = shared::Msg::new(shared::Action::Insert, rule);
            match send_to_daemon(msg) {
                Ok(_) => (),
                Err(msg) => println!("{}", msg)
            }
        },
        ActionType::Delete => {},
        ActionType::List => {}
    }
}
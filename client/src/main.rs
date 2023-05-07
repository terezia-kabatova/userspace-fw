/* client program */
extern crate serde;

use std::{os::unix::net::UnixStream, io::{Write, Read}};
use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    action_type: ActionType,
}

#[derive(Debug, serde::Serialize, clap::Args)]
pub struct RuleArgs {
    /// encapsulated protocol
    #[arg(value_enum, short, required = false, default_value_t = L4prot::Any)]
    protocol: L4prot,

    /// L4 source port
    #[arg(short, required = false, default_value_t = 0, requires = "protocol")] // a port cannot be specified without the transport layer type
    src_port: u16,

    /// L4 destination port
    #[arg(short, required = false, default_value_t = 0, requires = "protocol")]
    dst_port: u16,

    /// ICMP message type
    #[arg(short, required = false, default_value_t = 0, requires = "protocol")]
    icmp_type: u8,

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
}

#[derive(clap::Subcommand, Debug, serde::Serialize)]
pub enum ActionType {
    /// Insert a new rule
    Insert {
        /// index where the new rule should be inserted, if not specified, rule will be added at the end of the list
        #[arg(short, required = false, default_value = None)]
        at: Option<usize>,
        #[clap(flatten)]
        rule_args: RuleArgs
    },

    /// Delete a specified rule
    Delete {
        #[clap(flatten)]
        rule_args: RuleArgs
    },

    /// Delete a rule specified by number
    DeleteNum {
        #[arg(required = true)]
        rule_num: usize
    },

    /// List rules from a specified chain or all if no chain is specified
    List,

    /// Save the rules to a file
    Commit
}

#[derive(clap::ValueEnum, Debug, Clone, serde::Serialize)]
pub enum L4prot {
    TCP,
    UDP,
    ICMP,
    Any,
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
            if n == 0 {
                return Ok(0);
            }
            Ok(u32::MAX >> (32 - n)) // this evaluates to 32 bit unsigned integer with n rightmost bits being 1s
        }
        Err(_) => Err(String::from("The mask is not a valid number."))
    };
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
                address[idx] = n;
                idx += 1;
            }
            Err(_) => return Err(String::from("Part of the address is not a number between 0 and 255."))
        }
    }
    // the array is converted to the binary representation of the address
    return Ok(u32::from_le_bytes(address));
}


fn send_to_daemon(message: shared::Msg) -> String {
    // connect to daemon socket
    let mut response: String = String::new();
    let mut stream = match UnixStream::connect("/tmp/fw.sock") {
        Ok(it) => it,
        Err(_err) => {
            println!("{}", _err);
            return String::from("Could not connect to the socket");
        }
    };

    // serialize the new rule and send through the socket
    let v = serde_json::to_value(message).unwrap().to_string() + "\n";
    match stream.write_all(&v.into_bytes()) {
        Ok(it) => it,
        Err(_err) => return String::from("Could not write to the socket"),
    };

    // receive response from daemon
    match stream.read_to_string(&mut response) {
        Ok(_) => {
            return response;
        }
        Err(e) => {
            return format!("Failed to receive data: {}", e);
        }
    }
}

fn construct_rule(rule_args: &RuleArgs) -> shared::Rule {
    let l4: shared::L4protocols;
    let mut dst: u16 = 0;
    let mut src: u16 = 0;
    let mut icmp: u8 = 0;
    match rule_args.protocol {
        L4prot::TCP => {
            l4 = shared::L4protocols::TCP;
            dst = rule_args.dst_port;
            src = rule_args.src_port
        }
        L4prot::UDP => {
            l4 = shared::L4protocols::UDP;
            dst = rule_args.dst_port;
            src = rule_args.src_port
        }
        L4prot::ICMP => {
            l4 = shared::L4protocols::ICMP;
            icmp = rule_args.icmp_type;
        }
        _ => l4 = shared::L4protocols::Unknown
    }
    let verdict: bool;
    match rule_args.action {
        Verdict::Accept => verdict = true,
        Verdict::Drop => verdict = false
    }
    return shared::Rule::new(
        verdict,
        shared::IPversions::IPv4,
        rule_args.src_addr.clone(),
        rule_args.dst_addr.clone(),
        rule_args.src_mask.clone(),
        rule_args.dst_mask.clone(),
        l4,
        src,
        dst,
        icmp);
}

fn main() {
    let args = Args::parse();
    // interpret supplied arguments
    match &args.action_type {
        // insert
        ActionType::Insert { rule_args, at: idx } => {
            let msg: shared::Msg;
            match idx {
                Some(i) => {
                    let payload = serde_json::to_value(construct_rule(rule_args)).unwrap().to_string() + "\n";
                    msg = shared::Msg::new(shared::Action::InsertAt { idx: *i }, payload);
                }
                None => {
                    let payload = serde_json::to_value(construct_rule(rule_args)).unwrap().to_string() + "\n";
                    msg = shared::Msg::new(shared::Action::Insert, payload);
                }
            }
            println!("{}", send_to_daemon(msg));
        }
        ActionType::Delete { rule_args } => {
            let payload = serde_json::to_value(construct_rule(rule_args)).unwrap().to_string() + "\n";
            let msg = shared::Msg::new(shared::Action::Delete, payload);
            println!("{}", send_to_daemon(msg));
        }
        ActionType::DeleteNum { rule_num } => {
            let msg = shared::Msg::new(shared::Action::DeleteNum, rule_num.to_string());
            println!("{}", send_to_daemon(msg));
        }
        ActionType::List => {
            let msg = shared::Msg::new(shared::Action::List, String::new());
            let rules_serial = send_to_daemon(msg).into_bytes();
            let rules: Vec<shared::Rule> = serde_json::from_slice(&rules_serial).unwrap();
            for (i, rule) in rules.iter().enumerate() {
                println!("[{}] {}", i, rule.to_string());
            }
        }
        ActionType::Commit => {
            let msg = shared::Msg::new(shared::Action::Commit, String::new());
            println!("{}", send_to_daemon(msg));
        }
    }
}

//#[cfg(test)]
//mod client_tests;
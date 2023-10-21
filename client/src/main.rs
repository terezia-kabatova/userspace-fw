/* client program */
extern crate serde;

use clap::Parser;
use shared::IPversions::IPv4;
use shared::L4protocols::{TCP, UDP};
use shared::{L4protocols, Rule};
use crate::L4prot::ICMP;

mod msg_sender;

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
    return Ok(u32::from_be_bytes(address));
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
            let payload = serde_json::to_value(construct_rule(rule_args)).unwrap().to_string() + "\n";
            msg = shared::Msg::new(shared::Action::Insert { idx: *idx }, payload);
            println!("{}", msg_sender::MsgSender::send_to_daemon(msg));
        }
        ActionType::Delete { rule_args } => {
            let payload = serde_json::to_value(construct_rule(rule_args)).unwrap().to_string() + "\n";
            let msg = shared::Msg::new(shared::Action::Delete, payload);
            println!("{}",  msg_sender::MsgSender::send_to_daemon(msg));
        }
        ActionType::DeleteNum { rule_num } => {
            let msg = shared::Msg::new(shared::Action::DeleteNum, rule_num.to_string());
            println!("{}",  msg_sender::MsgSender::send_to_daemon(msg));
        }
        ActionType::List => {
            let msg = shared::Msg::new(shared::Action::List, String::new());
            let rules_serial =  msg_sender::MsgSender::send_to_daemon(msg).into_bytes();
            let rules: Vec<shared::Rule> = serde_json::from_slice(&rules_serial).unwrap();
            for (i, rule) in rules.iter().enumerate() {
                println!("[{}] {}", i, rule.to_string());
            }
        }
        ActionType::Commit => {
            let msg = shared::Msg::new(shared::Action::Commit, String::new());
            println!("{}",  msg_sender::MsgSender::send_to_daemon(msg));
        }
    }
}

#[test]
fn test_address_parser() {
    assert_eq!(address_parser("s4ect"), Err(String::from("The address does not have exactly four parts. (delimited by .)")));
    assert_eq!(address_parser("1.1.1.256"), Err(String::from("Part of the address is not a number between 0 and 255.")));
    assert_eq!(address_parser("-1.1.1.256"), Err(String::from("Part of the address is not a number between 0 and 255.")));
    assert_eq!(address_parser("192.168.1.1"), Ok(3232235777));
}

#[test]
fn test_mask_parser() {
    assert_eq!(mask_parser("45"), Err(String::from("The mask has too many bits.")));
    assert_eq!(mask_parser("a"), Err(String::from("The mask is not a valid number.")));
    assert_eq!(mask_parser("0"), Ok(0));
    assert_eq!(mask_parser("16"), Ok(65535));
}


#[test]
fn test_rule_constructor() {
    let mut args = RuleArgs{
        protocol: L4prot::TCP,
        action: Verdict::Accept,
        src_addr: 1,
        dst_addr: 2,
        src_mask: 3,
        dst_mask: 4,
        src_port: 5,
        dst_port: 6,
        icmp_type: 7
    };
    // ICMP type is ignored when L4 protocol is TCP or UDP
    assert_eq!(construct_rule(&args), Rule::new(true, IPv4, 1, 2, 3, 4, TCP, 5, 6, 0));

    args.protocol = L4prot::UDP;
    assert_eq!(construct_rule(&args), Rule::new(true, IPv4, 1, 2, 3, 4, L4protocols::UDP, 5, 6, 0));

    // ports are ignored when L4 protocol is ICMP
    args.protocol = ICMP;
    assert_eq!(construct_rule(&args), Rule::new(true, IPv4, 1, 2, 3, 4, L4protocols::ICMP, 0, 0, 7));
}
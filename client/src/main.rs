/* client program */

use clap::Parser;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[command(subcommand)]
    action_type: ActionType
}

#[derive(clap::Subcommand, Debug)]
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

        /// name of the target chain
        #[arg(required = true)]
        chain: String,

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

#[derive(clap::ValueEnum, Debug, Clone)]
pub enum L4prot {
    TCP,
    UDP,
    Any
}

// takes number of bits - n - and returns binary form of an address mask with n bits
fn mask_parser(input: &str) -> Result<u32, String> {
    match input.parse::<u32>() {
        Ok(n) => {
            // enforce max mask value
            if n > 32 {
                return Err(String::from("The mask has too many bits."));
            }
            return Ok(u32::MAX >> (32 - n)); // this evaluates to 32 bit unsigned integer with n rightmost bits being 1s
        },
        Err(_) => return Err(String::from("The mask is not a valid number."))
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
            Err(_) => return Result::Err(String::from("Part of the address is not a number between 0 and 255."))
        }
    }
    // the array is converted to the binary representation of the address
    return Ok(u32::from_le_bytes(address));
}

fn main() {
    let args = Args::parse();
    println!("{:?}", args);
}
extern crate serde;

use std::net::{IpAddr, Ipv4Addr};
use std::net::Ipv6Addr;
use clap::Parser;
use crate::IPmask::{IPv4, IPv6};

// helper enums for the PacketInfo enum
#[derive(Debug)]
#[derive(PartialEq, Clone)]
#[derive(serde::Serialize, serde::Deserialize)]
pub struct L3 {
    pub src_addr: IpAddr,
    pub dst_addr: IpAddr
}



#[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq, Clone)]
pub enum IPmask {
    IPv4(u32, u32),
    IPv6(u128, u128)
}

#[derive(Debug)]
#[derive(PartialEq, Clone)]
#[derive(serde::Serialize, serde::Deserialize)]
pub enum L4protocols {
    TCP {
        src_port: u16,
        dst_port: u16,
    },
    UDP {
        src_port: u16,
        dst_port: u16,
    },
    ICMP {
        icmp_type: u8
    },
    Unknown
}

impl L4protocols {
    fn to_string(&self) -> String {
        match self {
            L4protocols::Unknown =>  String::new(),
            L4protocols::ICMP { icmp_type } =>  format!("ICMP - type: {}", icmp_type),
            L4protocols::TCP { src_port, dst_port } => format!("TCP - src port: {} dst port: {}", src_port, dst_port),
            L4protocols::UDP { src_port, dst_port } => format!("UDP - src port: {} dst port: {}", src_port, dst_port)
        }
    }
}


#[derive(Debug)]
pub enum PacketVerdict {
    Accept,
    Drop,
    Undecided,
}


// struct for collecting info about the currently evaluated packet
// after all the info is collected, we compare it against the rules
#[derive(Debug, Clone)]
pub struct PacketInfo {
    pub version: L3,
    pub l4protocol: L4protocols
}

impl PacketInfo {
    pub fn new() -> PacketInfo {
        PacketInfo {
            version: L3{ src_addr: IpAddr::V4(Ipv4Addr::new(0,0,0,0)), dst_addr: IpAddr::V4(Ipv4Addr::new(0,0,0,0)) }, // TODO: think about the whole architecture
            l4protocol: L4protocols::Unknown
        }
    }
}


#[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq, Clone)]
pub struct Rule {
    permit: bool,
    l3: L3,
    l3_masks: IPmask,
    l4: L4protocols
}

// checks whether packet matches the rule
// currently supports only IPv4, rules for IPv6 will have to be in a separate structure, because of the IP address size (or change it here)
impl Rule {
    pub fn new(permit: bool, version: L3, l4protocol: L4protocols, masks: IPmask) -> Result<Rule, String> {
        match masks {
            IPmask::IPv4 { .. } => {
                if version.dst_addr.is_ipv6() || version.src_addr.is_ipv6() {
                    return Err(String::from("IP version does not match mask version"))
                }
            },
            IPmask::IPv6 { .. } => {
                if version.dst_addr.is_ipv4() || version.src_addr.is_ipv4() {
                    return Err(String::from("IP version does not match mask version"))
                }
            }
        }
        Ok(Rule{
            permit,
            l3: version,
            l3_masks: masks,
            l4: l4protocol
        })
    }

    fn check_ipv4(&self, l3info: &L3) -> bool {
        // match src addresses
        match (l3info.src_addr, self.l3.src_addr) {
            (IpAddr::V4(src1), IpAddr::V4(src2)) => {
                match self.l3_masks {
                    IPv4(src_mask, dst_mask) => {
                        if u32::from_be_bytes(src1.octets()) & src_mask != u32::from_be_bytes(src2.octets()) & src_mask {
                            return false;
                        }
                    }
                    IPv6(_, _) => return false // this is an unexpected state
                }
            }
            _ => {}
        }

        // match dst addresses
        match (l3info.dst_addr, self.l3.dst_addr) {
            (IpAddr::V4(dst1), IpAddr::V4(dst2)) => {
                match self.l3_masks {
                    IPv4(src_mask, dst_mask) => {
                        if u32::from_be_bytes(dst1.octets()) & dst_mask != u32::from_be_bytes(dst2.octets()) & dst_mask {
                            return false;
                        }
                    }
                    IPv6(_, _) => return false // this is an unexpected state
                }
            }
            _ => {}
        }
        return true
    }

    fn check_ipv6(&self, l3info: &L3) -> bool {
        // match src addresses
        match (l3info.src_addr, self.l3.src_addr) {
            (IpAddr::V6(src1), IpAddr::V6(src2)) => {
                match self.l3_masks {
                    IPv6(src_mask, dst_mask) => {
                        if u128::from_be_bytes(src1.octets()) & src_mask != u128::from_be_bytes(src2.octets()) & src_mask {
                            return false;
                        }
                    }
                    IPv4(_, _) => return false // this is an unexpected state
                }
            }
            _ => {}
        }

        // match dst addresses
        match (l3info.dst_addr, self.l3.dst_addr) {
            (IpAddr::V6(dst1), IpAddr::V6(dst2)) => {
                match self.l3_masks {
                    IPv6(src_mask, dst_mask) => {
                        if u128::from_be_bytes(dst1.octets()) & dst_mask != u128::from_be_bytes(dst2.octets()) & dst_mask {
                            return false;
                        }
                    }
                    IPv4(_, _) => return false // this is an unexpected state
                }
            }
            _ => {}
        }
        return true
    }

    fn check_l4(&self, l4info: &L4protocols) -> bool {
        match (&self.l4, l4info) {
            (L4protocols::TCP { src_port: src_port1, dst_port: dst_port1 },
                L4protocols::TCP { src_port: src_port2, dst_port: dst_port2 }) => {
                if src_port1 != src_port2 && *src_port1 != 0 {
                    return false;
                }
                if dst_port1 != dst_port2 && *dst_port1 != 0 {
                    return false;
                }
            },
            (L4protocols::UDP { src_port: src_port1, dst_port: dst_port1 },
                L4protocols::UDP { src_port: src_port2, dst_port: dst_port2 }) => {
                if src_port1 != src_port2 && *src_port1 != 0 {
                    return false;
                }
                if dst_port1 != dst_port2 && *dst_port1 != 0 {
                    return false;
                }
            },
            (L4protocols::ICMP { icmp_type: icmp_type1 },
                L4protocols::ICMP { icmp_type: icmp_type2 }) => {
                if icmp_type1 != icmp_type2 && *icmp_type1 != 0 {
                    return false;
                }
            }
            (_, _) => { // protocol did not match
                return false;
            }
        }
        return true;
    }

    pub fn check_packet(&self, packet: &mut PacketInfo) -> bool {
        println!("{:?}", self);
        println!("{:?}", packet);

        if !(self.check_ipv4(&packet.version) || self.check_ipv6(&packet.version)) {
            return false;
        }

        if !self.check_l4(&packet.l4protocol) {
            return false;
        }

        return true;
    }

    pub fn get_permit(&self) -> bool {
        return self.permit;
    }

    pub fn to_string(&self) -> String {

        let src_mask;
        let dst_mask;
        match self.l3_masks {
            IPv4(src, dst) => {
                src_mask = u32::count_ones(src);
                dst_mask = u32::count_ones(dst);
            }
            IPv6(src, dst) => {
                src_mask = u128::count_ones(src);
                dst_mask = u128::count_ones(dst);
            }
        }
        return format!("permit: {} src addr: {}/{} dst addr: {}/{} protocol: {}",
                       self.permit,
                       self.l3.src_addr.to_string(),
                       src_mask,
                       self.l3.dst_addr.to_string(),
                       dst_mask,
                       self.l4.to_string());
    }
}


#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub enum Action {
    Insert {
        idx: Option<usize>
    },
    Delete,
    DeleteNum,
    List,
    Commit
}

#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct Msg {
    pub action: Action,
    pub payload: String,
}

impl Msg {
    pub fn new(action: Action, rule: String) -> Msg {
        Msg { action, payload: rule }
    }
}

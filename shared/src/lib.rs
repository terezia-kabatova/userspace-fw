extern crate serde;

// helper enums for the PacketInfo enum
#[derive(Debug)]
#[derive(PartialEq)]
#[derive(serde::Serialize, serde::Deserialize)]
pub enum IPversions {
    IPv4,
    IPv6//,
    //Unknown
}

#[derive(Debug)]
#[derive(PartialEq)]
#[derive(serde::Serialize, serde::Deserialize)]
pub enum L4protocols {
    TCP,
    UDP,
    Unknown,
    ICMP,
}


#[derive(Debug)]
pub enum PacketVerdict {
    Accept,
    Drop,
    Undecided
}



// struct for collecting info about the currently evaluated packet
// after all the info is collected, we compare it against the rules
#[derive(Debug)]
pub struct PacketInfo {
    pub version: IPversions,
    pub src_addr: u32,
    pub dst_addr: u32,
    pub l4protocol: L4protocols,
    pub src_port: u16,
    pub dst_port: u16,
    pub icmp_type: u8
}

impl PacketInfo {

    pub fn new() -> PacketInfo {
        PacketInfo {
            version: IPversions::IPv4,
            src_addr: 0,
            dst_addr: 0,
            l4protocol: L4protocols::Unknown,
            src_port: 0,
            dst_port: 0,
            icmp_type: 0
        }
    }
}


#[derive(serde::Serialize, serde::Deserialize, Debug, PartialEq)]
pub struct Rule(bool, IPversions, u32, u32, u32, u32, L4protocols, u16, u16, u8);

// checks whether packet matches the rule
// currently supports only IPv4, rules for IPv6 will have to be in a separate structure, because of the IP address size (or change it here)
impl Rule {

    pub fn new(permit: bool,
               version: IPversions,
               src_addr: u32,
               dst_addr: u32,
               src_mask: u32,
               dst_mask: u32,
               l4protocol: L4protocols,
               src_port: u16,
               dst_port: u16,
               icmp_type: u8) -> Rule {
        Rule(permit, version, src_addr, src_mask, dst_addr, dst_mask, l4protocol, src_port, dst_port, icmp_type)
    }

    pub fn check_packet(&self, packet: &mut PacketInfo) -> bool {
        // the ip version does not match
        if self.1 != packet.version {
            return false;
        }

        // we comapare only the part specified by subnet mask;
        // TODO: the src_addr could be bitmasked in Rule constructor
        
        // src or dst address do not match
        if self.2 & self.3 != packet.src_addr & self.3 || self.4 & self.5 != packet.dst_addr & self.5 {
            return false;
        }

        // encapsulated protocol is ICMP
        if self.6 == L4protocols::ICMP && self.6 == packet.l4protocol {
            // icmp packet that matches type or the type is not specified in rule
            return self.9 == 0 || self.9 == packet.icmp_type;
        }
        // UDP or TCP
        if (self.6 == L4protocols::UDP || self.6 == L4protocols::TCP) && self.6 == packet.l4protocol {
            // the ports either match, or they are specified as 0 (don't care)
            return (self.7 == 0 || self.7 == packet.src_port) && (self.8 == 0 || self.8 == packet.dst_port);
        }
        return packet.l4protocol == L4protocols::Unknown;
    }

    pub fn get_permit(&self) -> bool {
        return self.0;
    }

    pub fn to_string(&self) -> String {
        let ip = serde_json::to_value(&self.1).unwrap().to_string();
        let src = self.2.to_le_bytes().iter().map(|i| i.to_string()+".").collect::<String>();
        let dst = self.4.to_le_bytes().iter().map(|i| i.to_string()+".").collect::<String>();
        let prot = serde_json::to_value(&self.6).unwrap().to_string();
        let details: String;
        match self.6 {
            L4protocols::Unknown => details = String::new(),
            L4protocols::ICMP => details = format!("icmp type: {}", self.9),
            _ => details = format!("src port: {} dst port: {}", self.7, self.8)
        }
        return format!("permit: {} {} src addr: {}/{} dst addr: {}/{} protocol: {} {}",
            self.0,
            ip,
            src.trim_end_matches("."),
            u32::count_ones(self.3),
            dst.trim_end_matches("."),
            u32::count_ones(self.5),
            prot,
            details)
    }
}


#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub enum Action {
    Insert,
    Delete,
    DeleteNum,
    List
}
#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct Msg {
    pub action: Action,
    pub payload: String
}

impl Msg {
    pub fn new(action: Action, rule: String) -> Msg {
        Msg { action, payload: rule}
    }
}

// helper enums for the PacketInfo enum
#[derive(Debug)]
#[derive(PartialEq)]
pub enum IPversions {
    IPv4,
    IPv6//,
    //Unknown
}

#[derive(Debug)]
#[derive(PartialEq)]
pub enum L4protocols {
    TCP,
    UDP,
    Unknown
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
    pub verdict: PacketVerdict
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
            verdict: PacketVerdict::Undecided
        }
    }
}

pub struct Rule {
    permit: bool,
    version: IPversions,
    src_addr: u32,
    src_mask: u32,
    dst_addr: u32,
    dst_mask: u32,
    l4protocol: L4protocols,
    src_port: u16,
    dst_port: u16
}

// checks whether packet matches the rule
// currently supports only IPv4, rules for IPv6 need to be in separate structure, because of the IP address size (or change it here)
impl Rule {

 pub fn new(permit: bool,
            version: IPversions,
            src_addr: u32,
            dst_addr: u32,
            src_mask: u32,
            dst_mask: u32,
            l4protocol: L4protocols,
            src_port: u16,
            dst_port: u16) -> Rule {
        Rule {
            permit,
            version,
            src_addr,
            src_mask,
            dst_addr,
            dst_mask,
            l4protocol,
            src_port,
            dst_port
        }
    }

    pub fn check_packet(&self, packet: &mut PacketInfo) -> bool {
        self.version == packet.version &&
        // we comapare only the part specified by subnet mask; TODO: the src_addr could be bitmasked in Rule constructor
        self.src_addr & self.src_mask == packet.src_addr & self.src_mask &&
        self.dst_addr & self.dst_mask == packet.dst_addr & self.dst_mask &&
        (self.l4protocol == L4protocols::Unknown ||
         (self.l4protocol == packet.l4protocol &&
          ((self.src_port == packet.src_port) || self.src_port == 0 ) && // the ports either match, or they are specified as 0 (don't care)
          ((self.dst_port == packet.dst_port) || self.dst_port == 0 )))
    }

    pub fn get_permit(&self) -> bool {
        return self.permit;
    }
}

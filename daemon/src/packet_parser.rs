use shared::IPversions::IPv4;
use shared::{IPversions, L4protocols, PacketInfo};

// enums for L3 and L4 header indexing
enum L3fields {
    VERSION = 0,
    ProtocolV4 = 9,
    SrcAddrV4 = 12,
    DstAddrV4 = 16,
}

enum L4fields {
    SrcPort = 0,
    DstPort = 2,
}

pub struct PacketParser {
    packet: Box<[u8]>,
    l4header_start: usize,
    packet_info: shared::PacketInfo
}

impl PacketParser {
    pub fn new() -> PacketParser {
        let p = [0u8];
        PacketParser{
            packet: p.into(),
            l4header_start: 0,
            packet_info: PacketInfo::new()
        }
    }

    pub fn get_packet_info(&mut self) -> PacketInfo {
        return self.packet_info.clone();
    }

    pub fn process_packet(&mut self, packet: &[u8])  {
        self.packet_info = PacketInfo::new();
        self.packet = packet.clone().into();


        let version = self.packet[L3fields::VERSION as usize];

        match version & 0b11110000 {    // only the first four bits represent IP version, so we use a bitmask

            0b01000000 => {
                self.packet_info.version = shared::IPversions::IPv4;
                self.process_ipv4_packet()
            }  // 0100 0000 - the IP version is 4

            0b01100000 => {
                self.packet_info.version = shared::IPversions::IPv6;
                self.process_ipv6_packet();
            }  // 0110 0000 - the IP version is 6

            _ => println!("received unknown IP version packet.") // TODO: think about this, whether the default info in packet is valid
        }
    }


    fn process_icmp_packet(&mut self) {
        self.packet_info.icmp_type = self.packet[self.l4header_start];
        //println!("icmp");
    }

    fn process_ipv4_packet(&mut self) {
        // the src and dst ipv4 addresses are prepared as 4 byte slices and converted to 32 bit integers (easy masking) for matching
        let src_slice = &self.packet[L3fields::SrcAddrV4 as usize..L3fields::SrcAddrV4 as usize + 4];
        let dst_slice = &self.packet[L3fields::DstAddrV4 as usize..L3fields::DstAddrV4 as usize + 4];

        let mut src: [u8; 4] = [0; 4];
        src.clone_from_slice(src_slice);

        let mut dst: [u8; 4] = [0; 4];
        dst.clone_from_slice(dst_slice);

        self.packet_info.src_addr = u32::from_be_bytes(src);
        self.packet_info.dst_addr = u32::from_be_bytes(dst);


        // calculation of the header size, so we pass only the payload to the next function
        self.l4header_start= ((self.packet[0] & 0b00001111) * 4) as usize;
        self.process_l4_prot();
    }

    #[allow(unused_variables)]
    fn process_ipv6_packet(&mut self) {
        // todo: dual stack support
    }

    fn process_l4_prot(&mut self) {
        match &self.packet[L3fields::ProtocolV4 as usize] {
            // maybe add option to ban specific protocols

            1 => {
                self.packet_info.l4protocol = shared::L4protocols::ICMP;
                self.process_icmp_packet();
            }
            6 => {
                self.packet_info.l4protocol = shared::L4protocols::TCP;
                self.process_tcp()
            }
            17 => {
                self.packet_info.l4protocol = shared::L4protocols::UDP;
                self.process_udp()
            }
            _ => println!("received an unknown encapsulated protocol.")
        }
    }

    fn process_tcp(&mut self) {
        self.extract_ports();
    }


    // this is just temporary, the L4 protocols will get more features in the future
    fn process_udp(&mut self) {
        self.extract_ports();
    }

    fn extract_ports(&mut self) {
        let src_port = &self.packet[L4fields::SrcPort as usize + self.l4header_start..L4fields::SrcPort as usize + 2 + self.l4header_start];
        let dst_port = &self.packet[L4fields::DstPort as usize + self.l4header_start..L4fields::DstPort as usize + 2 + self.l4header_start];

        self.packet_info.src_port = ((src_port[0] as u16) << 8) | src_port[1] as u16;
        self.packet_info.dst_port = ((dst_port[0] as u16) << 8) | dst_port[1] as u16;
    }
}


#[test]
fn parse_tcp_icmp_udp() {
    let mut parser = PacketParser::new();
    let xs: [u8; 52] = [
        0x45, 0x00, /* E. */
        0x00, 0x34, 0x44, 0xf6, 0x00, 0x00, 0x7a, 0x06, /* .4D...z. */
        0x85, 0xad, 0x8e, 0xfb, 0x25, 0x63, 0xc0, 0xa8, /* ....%c.. */
        0x01, 0x1a, 0x00, 0x50, 0x0e, 0x8e, 0x3b, 0xe8, /* ...P..;. */
        0x30, 0x93, 0xd8, 0x31, 0xd8, 0xf1, 0x80, 0x10, /* 0..1.... */
        0x01, 0x15, 0x73, 0xc4, 0x00, 0x00, 0x01, 0x01, /* ..s..... */
        0x05, 0x0a, 0xd8, 0x31, 0xd8, 0xf0, 0xd8, 0x31, /* ...1...1 */
        0xd8, 0xf1                                      /* .. */
    ];
    parser.process_packet(&xs);
    assert_eq!(parser.packet_info.version, IPversions::IPv4);
    assert_eq!(parser.packet_info.dst_port, 3726);
    assert_eq!(parser.packet_info.src_port, 80);
    assert_eq!(parser.packet_info.l4protocol, L4protocols::TCP);
    assert_eq!(parser.packet_info.src_addr, 2398823779);
    assert_eq!(parser.packet_info.dst_addr, 3232235802);

    let xs: [u8; 60] = [
        0x45, 0x00, /* E. */
        0x00, 0x3c, 0x0f, 0x6c, 0x00, 0x00, 0x80, 0x01, /* .<.l.... */
        0x00, 0x00, 0xc0, 0xa8, 0x01, 0x1a, 0xc0, 0xa8, /* ........ */
        0x01, 0x01, 0x08, 0x00, 0x4c, 0xc7, 0x00, 0x01, /* ....L... */
        0x00, 0x94, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, /* ..abcdef */
        0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, /* ghijklmn */
        0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, /* opqrstuv */
        0x77, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, /* wabcdefg */
        0x68, 0x69                                      /* hi */
    ];
    parser.process_packet(&xs);
    assert_eq!(parser.packet_info.version, IPversions::IPv4);
    assert_eq!(parser.packet_info.dst_port, 0);
    assert_eq!(parser.packet_info.src_port, 0);
    assert_eq!(parser.packet_info.l4protocol, L4protocols::ICMP);
    assert_eq!(parser.packet_info.src_addr, 3232235802);
    assert_eq!(parser.packet_info.dst_addr, 3232235777);


    let xs: [u8; 72] = [0x45, 0x00, /* E. */
    0x00, 0x48, 0x5d, 0x68, 0x00, 0x00, 0x80, 0x11, /* .H]h.... */
    0x58, 0x42, 0xc0, 0xa8, 0x01, 0xab, 0xc0, 0xa8, /* XB...... */
    0x01, 0xff, 0xe1, 0x15, 0xe1, 0x15, 0x00, 0x34, /* .......4 */
    0x6e, 0x1d, 0x53, 0x70, 0x6f, 0x74, 0x55, 0x64, /* n.SpotUd */
    0x70, 0x30, 0x4e, 0xf9, 0x81, 0x21, 0x7e, 0x6a, /* p0N..!~j */
    0xd9, 0x40, 0x00, 0x01, 0x00, 0x04, 0x48, 0x95, /* .@....H. */
    0xc2, 0x03, 0xd5, 0x90, 0x17, 0x01, 0x0c, 0x01, /* ........ */
    0x44, 0xc1, 0xac, 0xe5, 0x1d, 0xfc, 0xb9, 0x8c, /* D....... */
    0xa0, 0xf3, 0x6d, 0x81, 0xbf, 0x2c              /* ..m.., */
    ];

    parser.process_packet(&xs);
    assert_eq!(parser.packet_info.version, IPversions::IPv4);
    assert_eq!(parser.packet_info.dst_port, 57621);
    assert_eq!(parser.packet_info.src_port, 57621);
    assert_eq!(parser.packet_info.l4protocol, L4protocols::UDP);
    assert_eq!(parser.packet_info.src_addr, 3232235947);
    assert_eq!(parser.packet_info.dst_addr, 3232236031);
}
/*
the data structure for storing rules
will be instantiated in the main() in daemon/main.rs and sent to the threads
*/


use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use nfq::Verdict;
use nfq::Verdict::Accept;
use shared::L4protocols::{ICMP, TCP, UDP};
use shared::{IPmask, L3, L4protocols, PacketInfo, Rule};
use shared::PacketVerdict::Drop;
use super::rule_manager_trait::RuleManagerTrait;


// standard list implementation
pub struct ListRuleManager {
    rules: Vec<shared::Rule>,
    default_verdict: nfq::Verdict,
}

impl ListRuleManager {
    pub(crate) fn new(default_action: nfq::Verdict) -> ListRuleManager {
        ListRuleManager { rules: Vec::new(), default_verdict: default_action }
    }
}

impl RuleManagerTrait for ListRuleManager {
    fn get_rule_count(&self) -> usize {
        return self.rules.len();
    }

    // fn add_rule(&mut self, rule: shared::Rule) -> Result<(), String> {
    //     self.rules.push(rule);
    //     Ok(())
    // }

    fn add_rule_at(&mut self, idx: usize, rule: shared::Rule) -> Result<(), String> {
        if idx >= self.rules.len() {
            // return Err("index out of bounds".to_string());
            self.rules.push(rule);
            return Ok(());
        }
        self.rules.insert(idx, rule);
        Ok(())
    }

    fn remove_rule(&mut self, rule: shared::Rule) -> Result<(), String> {
        self.rules.retain(|rul| rul != &rule);
        Ok(())
    }

    fn remove_rule_num(&mut self, rule: usize) -> Result<(), String> {
        if rule >= self.rules.len() {
            return Err("index out of bounds".to_string());
        }
        self.rules.remove(rule);
        Ok(())
    }

    fn check_packet(&self, packet: &mut shared::PacketInfo) -> nfq::Verdict {
        for rule in self.rules.iter() {
            if rule.check_packet(packet) {
                if rule.get_permit() {
                    return nfq::Verdict::Accept;
                }
                return nfq::Verdict::Drop;
            }
        }
        self.default_verdict
    }

    fn show(&self) -> String {
        return serde_json::to_value(&self.rules).unwrap().to_string();
    }

    fn set_default_action(&mut self, verdict: Verdict) -> Result<(), String> {
        self.default_verdict = verdict;
        return Ok(());
    }
}

#[test]
fn rule_management(){
    let mut rule_mgr = ListRuleManager::new(Accept);
    let rule1 = Rule::new(false,
                          L3 { src_addr: IpAddr::V4(Ipv4Addr::from(0)), dst_addr: IpAddr::V4(Ipv4Addr::from(0)) },
                          L4protocols::ICMP {icmp_type: 1},
                          IPmask::IPv4 { 0: 0, 1: 0 }).unwrap();
    let rule2 = Rule::new(false,
                          L3 { src_addr: IpAddr::V4(Ipv4Addr::from(0)), dst_addr: IpAddr::V4(Ipv4Addr::from(0)) },
                          L4protocols::ICMP {icmp_type: 2},
                          IPmask::IPv4 { 0: 0, 1: 0 }).unwrap();
    let rule3  = Rule::new(false,
                           L3 { src_addr: IpAddr::V4(Ipv4Addr::from(0)), dst_addr: IpAddr::V4(Ipv4Addr::from(0)) },
                           L4protocols::ICMP {icmp_type: 3},
                           IPmask::IPv4 { 0: 0, 1: 0 }).unwrap();
    rule_mgr.add_rule_at(0, rule1);
    rule_mgr.add_rule_at(0, rule2);
    rule_mgr.add_rule_at(0, rule3);
    assert_eq!(rule_mgr.get_rule_count(), 3);
    assert_eq!(rule_mgr.show(), r#"[{"L4":{"ICMP":{"icmp_type":3}},"l3":{"IPv4":{"dst_addr":"0.0.0.0","src_addr":"0.0.0.0"}},"l3_masks":{"IPv4":{"dst_mask":0,"src_mask":0}},"permit":false},{"L4":{"ICMP":{"icmp_type":2}},"l3":{"IPv4":{"dst_addr":"0.0.0.0","src_addr":"0.0.0.0"}},"l3_masks":{"IPv4":{"dst_mask":0,"src_mask":0}},"permit":false},{"L4":{"ICMP":{"icmp_type":1}},"l3":{"IPv4":{"dst_addr":"0.0.0.0","src_addr":"0.0.0.0"}},"l3_masks":{"IPv4":{"dst_mask":0,"src_mask":0}},"permit":false}]"#);

    let rule2 = Rule::new(false,
                          L3 { src_addr: Ipv4Addr(Ipv4Addr::from(0)), dst_addr: Ipv4Addr(Ipv4Addr::from(0)) },
                          L4protocols::ICMP {icmp_type: 2},
                          IPmask::IPv4 { 0: 0, 1: 0 }).unwrap();
    rule_mgr.remove_rule(rule2);
    assert_eq!(rule_mgr.get_rule_count(), 2);
    assert_eq!(rule_mgr.show(), r#"[{"L4":{"ICMP":{"icmp_type":3}},"l3":{"IPv4":{"dst_addr":"0.0.0.0","src_addr":"0.0.0.0"}},"l3_masks":{"IPv4":{"dst_mask":0,"src_mask":0}},"permit":false},{"L4":{"ICMP":{"icmp_type":1}},"l3":{"IPv4":{"dst_addr":"0.0.0.0","src_addr":"0.0.0.0"}},"l3_masks":{"IPv4":{"dst_mask":0,"src_mask":0}},"permit":false}]"#);

    rule_mgr.remove_rule_num(6);
    assert_eq!(rule_mgr.get_rule_count(), 2);


    rule_mgr.remove_rule_num(0);
    assert_eq!(rule_mgr.get_rule_count(), 1);
    assert_eq!(rule_mgr.show(), r#"[{"L4":{"ICMP":{"icmp_type":1}},"l3":{"IPv4":{"dst_addr":"0.0.0.0","src_addr":"0.0.0.0"}},"l3_masks":{"IPv4":{"dst_mask":0,"src_mask":0}},"permit":false}]"#);
}

#[test]
fn packet_check_default_verdict() {
    let mut rule_mgr = ListRuleManager::new(Accept);
    let mut rules: Vec<Rule> = Vec::new();
    rules.push(Rule::new(false,
                         L3 { src_addr: IpAddr::V6(Ipv6Addr::from(0)), dst_addr: IpAddr::V6(Ipv6Addr::from(0)) },
                         L4protocols::TCP { src_port: 0, dst_port: 0 },
                         IPmask::IPv6 { 0: 0, 1: 0 }).unwrap()); // wrong version
    rules.push(Rule::new(false,
                         L3 { src_addr: IpAddr::V4(Ipv4Addr::from(0)), dst_addr: IpAddr::V4(Ipv4Addr::from(0)) },
                         L4protocols::UDP { src_port: 0, dst_port: 0 },
                         IPmask::IPv4 { 0: 0, 1: 0 }).unwrap()); // wrong l4 protocol
    rules.push(Rule::new(false,
                         L3 { src_addr: IpAddr::V6(Ipv6Addr::from(0)), dst_addr: IpAddr::V6(Ipv6Addr::from(0)) },
                         L4protocols::ICMP {icmp_type: 0},
                         IPmask::IPv6 { 0: 0, 1: 0 }).unwrap()); // wrong l4 protocol
    rules.push(Rule::new(false,
                         L3 { src_addr: IpAddr::V4(Ipv4Addr::from(0)), dst_addr: IpAddr::V4(Ipv4Addr::from(0)) },
                         L4protocols::TCP { src_port: 443, dst_port: 80 },
                         IPmask::IPv4 { 0: 0, 1: 0 }).unwrap()); // wrong src port
    rules.push(Rule::new(false,
                         L3 { src_addr: IpAddr::V4(Ipv4Addr::from(0)), dst_addr: IpAddr::V4(Ipv4Addr::from(0)) },
                         L4protocols::TCP { src_port: 80, dst_port: 25 },
                         IPmask::IPv4 { 0: 0, 1: 0 }).unwrap()); // wrong dst port
    rules.push(Rule::new(false,
                         L3::IPv4 { src_addr: IpAddr::V4(Ipv4Addr::from(0xC1A80101)), dst_addr: IpAddr::V4(Ipv4Addr::from(0xC0A80101)) },
                         L4protocols::TCP { src_port: 443, dst_port: 80 },
                         IPmask::IPv4 { 0: 0, 1: 0 }).unwrap()); // wrong src addr
    for rule in rules {
        rule_mgr.add_rule_at(rule_mgr.get_rule_count(), rule);
    }


    let mut packet = PacketInfo::new();
    packet.l4protocol = TCP { src_port: 80, dst_port: 80 };
    packet.version = IPv4 { src_addr: Ipv4Addr::from(0xC0A80101), dst_addr: Ipv4Addr::from(0xC0A80101) };
    assert_eq!(rule_mgr.check_packet(&mut packet), Accept);

}

// #[test]
// fn packet_check_TCP_1() {
//     let mut rule_mgr = ListRuleManager::new(Accept);
//     let mut rules: Vec<Rule> = Vec::new();
//     rules.push(Rule::new(false, IPv4, 0xC0A80102, 0xC0A80101, 8, 32, TCP, 80, 0, 0)); // src addr wrong without mask
//     for rule in rules {
//         rule_mgr.add_rule_at(rule_mgr.get_rule_count(), rule);
//     }
//
//
//     let mut packet = PacketInfo::new();
//     packet.src_addr = 0xC0A80101;
//     packet.dst_addr = 0xC0A80101;
//     packet.src_port = 80;
//     packet.dst_port = 80;
//     packet.l4protocol = TCP;
//     packet.version = IPv4;
//     assert_eq!(rule_mgr.check_packet(&mut packet), nfq::Verdict::Drop);
//
// }
//
// #[test]
// fn packet_check_TCP_2() {
//     let mut rule_mgr = ListRuleManager::new(Accept);
//     let mut rules: Vec<Rule> = Vec::new();
//     rules.push(Rule::new(false, IPv4, 0xC0A80101, 0xC0A80101, 8, 32, TCP, 80, 443, 0)); // wrong src addr
//     for rule in rules {
//         rule_mgr.add_rule_at(rule_mgr.get_rule_count(), rule);
//     }
//
//
//     let mut packet = PacketInfo::new();
//     packet.src_addr = 0xC0A80101;
//     packet.dst_addr = 0xC0A80101;
//     packet.src_port = 80;
//     packet.dst_port = 443;
//     packet.l4protocol = UDP;
//     packet.version = IPv4;
//     assert_eq!(rule_mgr.check_packet(&mut packet), nfq::Verdict::Accept);
//
// }
//
//
// #[test]
// fn packet_check_unknown() {
//     let mut rule_mgr = ListRuleManager::new(Accept);
//     let mut rules: Vec<Rule> = Vec::new();
//     rules.push(Rule::new(false, Unknown, 0, 0, 0, 0, L4protocols::Unknown, 0, 0, 0));
//     for rule in rules {
//         rule_mgr.add_rule_at(rule_mgr.get_rule_count(), rule);
//     }
//
//
//     let mut packet = PacketInfo::new();
//     packet.src_addr = 0xC0A80101;
//     packet.dst_addr = 0xC0A80101;
//     packet.src_port = 80;
//     packet.dst_port = 443;
//     packet.l4protocol = UDP;
//     packet.version = IPv4;
//     assert_eq!(rule_mgr.check_packet(&mut packet), nfq::Verdict::Accept);
//
//     let mut packet = PacketInfo::new();
//     packet.src_addr = 0xC0A80101;
//     packet.dst_addr = 0xC0A80101;
//     packet.src_port = 80;
//     packet.dst_port = 443;
//     packet.l4protocol = UDP;
//     packet.version = Unknown;
//     assert_eq!(rule_mgr.check_packet(&mut packet), nfq::Verdict::Drop);
//
// }
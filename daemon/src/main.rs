/* multi-threading version*/

extern crate serde;
extern crate yaml_rust;

use rule_manager::rule_manager_trait::RuleManagerTrait;
use yaml_rust::{YamlLoader};
use nfq::{Queue, Verdict};
use network_interface::{NetworkInterface, NetworkInterfaceConfig};
use shared::Rule;
use signal_hook::low_level::exit;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::{thread, fs};
use std::os::unix::net::{UnixListener, UnixStream};
use std::net::Shutdown;
use std::io::{BufReader, BufRead, Write};
use std::sync::{Arc, RwLock};
use rule_manager::list_rule_manager;

mod thread_safe_wrapper;
mod rule_manager;

// enums for L3 and L4 header indexing
enum PacketField {
    VERSION = 0,
    ProtocolV4 = 9,
    SrcAddrV4 = 12,
    DstAddrV4 = 16,
}

enum L4fields {
    SrcPort = 0,
    DstPort = 2,
}


pub struct Daemon;


impl Daemon {
    // helper functions for packet parsing


    fn process_icmp_packet(packet: &[u8], info: &mut shared::PacketInfo) {
        info.icmp_type = packet[0];
        println!("icmp");
    }

    fn process_ipv4_packet(packet: &[u8], info: &mut shared::PacketInfo) {
        // the src and dst ipv4 addresses are prepared as 4 byte slices and converted to 32 bit integers (easy masking) for matching
        let src_slice = &packet[PacketField::SrcAddrV4 as usize..PacketField::SrcAddrV4 as usize + 4];
        let dst_slice = &packet[PacketField::DstAddrV4 as usize..PacketField::DstAddrV4 as usize + 4];

        let mut src: [u8; 4] = [0; 4];
        src.clone_from_slice(src_slice);

        let mut dst: [u8; 4] = [0; 4];
        dst.clone_from_slice(dst_slice);

        info.src_addr = u32::from_le_bytes(src);
        info.dst_addr = u32::from_le_bytes(dst);


        // calculation of the header size, so we pass only the payload to the next function
        let header_size = ((packet[0] & 0b00001111) * 4) as usize;
        match &packet[PacketField::ProtocolV4 as usize] {
            // maybe add option to ban specific protocols

            1 => {
                info.l4protocol = shared::L4protocols::ICMP;
                Self::process_icmp_packet(&packet[header_size..], info);
            }
            6 => {
                info.l4protocol = shared::L4protocols::TCP;
                Self::process_tcp(&packet[header_size..], info)
            }
            17 => {
                info.l4protocol = shared::L4protocols::UDP;
                Self::process_udp(&packet[header_size..], info)
            }
            _ => println!("received an unknown encapsulated protocol.")
        }
    }

    #[allow(unused_variables)]
    fn process_ipv6_packet(packet: &[u8], info: &mut shared::PacketInfo) {
        // todo: dual stack support
    }

    fn process_tcp(packet: &[u8], info: &mut shared::PacketInfo) {
        let src_port = &packet[L4fields::SrcPort as usize..L4fields::SrcPort as usize + 2];
        let dst_port = &packet[L4fields::DstPort as usize..L4fields::DstPort as usize + 2];

        info.src_port = ((src_port[0] as u16) << 8) | src_port[1] as u16;
        info.dst_port = ((dst_port[0] as u16) << 8) | dst_port[1] as u16;
    }


    // this is just temporary, the L4 protocols will get more features in the future
    fn process_udp(packet: &[u8], info: &mut shared::PacketInfo) {
        let src_port = &packet[L4fields::SrcPort as usize..L4fields::SrcPort as usize + 2];
        let dst_port = &packet[L4fields::DstPort as usize..L4fields::DstPort as usize + 2];

        info.src_port = ((src_port[0] as u16) << 8) | src_port[1] as u16;
        info.dst_port = ((dst_port[0] as u16) << 8) | dst_port[1] as u16;
    }


    // helper functions for rule management
    fn parse_new_rule<RuleManager: RuleManagerTrait>(msg: Vec<u8>, rules: &Arc<RwLock<RuleManager>>) -> Result<String, String> {
        if msg.is_empty() {
            return Err(String::from("Received message was empty."));
        }
        let mut write_rules;
        let mut response: String = String::from("success");
        match rules.write() {
            Ok(rw_rules) => write_rules = rw_rules,
            Err(msg) => return Err(format!("could not obtain write lock on rule structure: {}", msg.to_string()))
        }
        let parser_msg: shared::Msg;
        match serde_json::from_slice(&msg[..]) {
            Ok(msg) => parser_msg = msg,
            Err(err_msg) => return Err(format!("an error occurred during deserialization: {}", err_msg.to_string()))
        }
        match parser_msg.action {
            shared::Action::Insert => {
                let rule: Rule;
                match serde_json::from_str::<Rule>(&parser_msg.payload) {
                    Ok(r) => rule = r,
                    Err(err_msg) => return Err(format!("an error occurred during rule deserialization: {}", err_msg.to_string()))
                }
                match write_rules.add_rule(rule) {
                    Ok(_) => (),
                    Err(err_msg) => return Err(format!("an error occurred during rule insertion: {}", err_msg.to_string()))
                }
            }

            shared::Action::Delete => {
                let rule: Rule;
                match serde_json::from_str::<Rule>(&parser_msg.payload) {
                    Ok(r) => rule = r,
                    Err(err_msg) => return Err(format!("an error occurred during rule deserialization: {}", err_msg.to_string()))
                }
                match write_rules.remove_rule(rule) {
                    Ok(_) => (),
                    Err(err_msg) => return Err(format!("an error occurred during rule deletion: {}", err_msg.to_string()))
                }
            }

            shared::Action::DeleteNum => {
                let rule: usize;
                match parser_msg.payload.parse::<usize>() {
                    Ok(r) => rule = r,
                    Err(err_msg) => return Err(format!("an error occurred during rule number deserialization: {}", err_msg.to_string()))
                }
                match write_rules.remove_rule_num(rule) {
                    Ok(_) => (),
                    Err(err_msg) => return Err(format!("an error occurred during rule deletion: {}", err_msg.to_string()))
                }
            }

            shared::Action::List => {
                response = write_rules.show();
            }
        }
        println!("{}", write_rules.show());
        Ok(response)
    }

    // function, that will run in the unix socket thread - used for communication with user
    fn socket_thread<RuleManager: RuleManagerTrait>(term: thread_safe_wrapper::ThreadSafeRead<Arc<AtomicBool>>, rules: Arc<RwLock<RuleManager>>) -> std::io::Result<()> {
        // the socket may or may not be present
        std::fs::remove_file("/tmp/fw.sock");
        println!("starting socket thread");
        // initialize
        let listener = match UnixListener::bind("/tmp/fw.sock") {
            Err(_) => panic!("failed to bind socket"),
            Ok(stream) => stream,
        };

        // accept connections until SIGTERM is issued
        // TODO: protocol documentation
        while !term.read().load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((mut socket, _addr)) => {

                    // read the message
                    let mut response = String::new();
                    let mut bf = BufReader::new(&socket);
                    bf.read_line(&mut response).unwrap();

                    println!("{}", response.as_str());

                    match response.as_str() {
                        // we received the finishing message
                        "end\n" => (),
                        // deserialize the received rule
                        _ => {
                            let ack: String;
                            match Self::parse_new_rule(response.into_bytes(), &rules) {
                                Ok(msg) => ack = msg,
                                Err(msg) => ack = msg
                            }

                            // send response
                            socket.write_all(&ack.into_bytes()).unwrap();
                        }
                    }
                }
                Err(e) => println!("accept function failed: {}", e),
            }
        }
        // clean up when terminating
        std::fs::remove_file("/tmp/fw.sock").unwrap();
        println!("stopping loop");
        Ok(())
    }

    // function, that will run in the nfqueue thread - used for processing packets from queue

    fn queue_thread<RuleManager: RuleManagerTrait>(term: thread_safe_wrapper::ThreadSafeRead<Arc<AtomicBool>>, rules: thread_safe_wrapper::ThreadSafeRead<RuleManager>) {
        println!("starting queue thread");

        let mut queue: Queue;
        match Queue::open() {
            Ok(q) => queue = q,
            Err(err_msg) => {
                eprintln!("an error occurred while opening queue: {}", err_msg);
                return;
            }
        }
        match queue.bind(0) {
            Ok(_) => (),
            Err(err_msg) => {
                eprintln!("an error occurred while binding to queue: {}", err_msg);
                return;
            }
        }
        while !term.read().load(Ordering::Relaxed) {
            let mut msg;
            match queue.recv() {
                Ok(packet) => msg = packet,
                Err(err_msg) => {
                    eprintln!("an error occurred while receiving packet from queue: {}", err_msg);
                    continue;
                }
            }
            let packet = msg.get_payload();
            let version = packet[PacketField::VERSION as usize];
            let mut packet_info = shared::PacketInfo::new();

            match version & 0b11110000 {    // only the first four bits represent IP version, so we use a bitmask

                0b01000000 => {
                    packet_info.version = shared::IPversions::IPv4;
                    Self::process_ipv4_packet(packet, &mut packet_info)
                }  // 0100 0000 - the IP version is 4

                0b01100000 => {
                    packet_info.version = shared::IPversions::IPv6;
                    Self::process_ipv6_packet(packet, &mut packet_info)
                }  // 0110 0000 - the IP version is 6

                _ => println!("received unknown IP version packet.")
            }


            // now we have all the information needed to check the packet against the rules
            let read_rules = rules.read();
            let verdict = read_rules.check_packet(&mut packet_info);
            msg.set_verdict(verdict);

            match queue.verdict(msg) {
                Ok(_) => (),
                Err(msg) => eprintln!("could not set verdict for packet: {}", msg)
            }
        }
        println!("stopping loop");
    }


    // this function initiates the iptables queue, both threads and SIGTERM hook
    // after SIGTERM is issued, performs graceful shutdown

    pub fn run_filter() -> Result<(), std::io::Error> {


        // create shared variable for terminating
        let term_rw = Arc::new(AtomicBool::new(false));

        match signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&term_rw)) {
            Ok(_) => (),
            Err(msg) => {
                eprintln!("an error occurred while registering signal hook: {}", msg);
                exit(1);
            }
        }
        let term = Arc::new(RwLock::new(term_rw));


        // initialize iptables rule
        let ipt: iptables::IPTables;
        match iptables::new(false) {
            Ok(iptables) => ipt = iptables,
            Err(msg) => {
                eprintln!("an error occurred while initiating iptables object: {}", msg);
                exit(1)
            }
        }

        let interfaces = NetworkInterface::show().unwrap().iter().map(|i| i.name.clone()).collect::<Vec<String>>();
        let config: String;
        match fs::read_to_string("/etc/usfw/fw.yaml") {
            Ok(cfg) => config = cfg,
            Err(msg) => {
                eprintln!("an error occurred while reading config file: {}", msg);
                exit(1)
            }
        }
        let docs: yaml_rust::Yaml;
        match YamlLoader::load_from_str(&config) {
            Ok(y) => docs = y[0].clone(),
            Err(msg) => {
                eprintln!("an error occurred while parsing config file: {}", msg);
                exit(1)
            }
        }

        // prepare structures for parsing config file
        let mut active_filter: HashMap<String, Vec<String>> = HashMap::new();
        let valid_chains = ["INPUT", "OUTPUT", "FORWARD"];

        // parse config file
        match docs["manage_iptables"].as_bool() {
            Some(manage) => {
                // the daemon will insert the iptables rules
                if manage {
                    let ifaces;
                    match docs["filter"].as_hash() {
                        Some(ifcs) => ifaces = ifcs,
                        None => {
                            eprintln!("manage_iptables is true, but could not read filter section");
                            exit(1)
                        }
                    }
                    // find all valid interface specifications
                    let valid_ifaces: Vec<String> = ifaces.keys().into_iter()
                        .map(|i| String::from(i.as_str().unwrap()))
                        .filter(|i| interfaces.contains(&i))
                        .collect();
                    if valid_ifaces.is_empty() {
                        eprintln!("at least one valid interface should be specified when manage_iptables option is true");
                        exit(1);
                    }
                    for iface in ifaces.keys() {
                        let i;
                        match iface.as_str() {
                            Some(x) => i = x,
                            None => {
                                eprintln!("could not read interface from config file");
                                continue;
                            }
                        }

                        let chains = ifaces[iface].as_vec().unwrap().iter()
                            .map(|i| i.as_str().unwrap().to_uppercase())
                            .filter(|i| valid_chains.contains(&i.as_str()))
                            .collect::<Vec<String>>();


                        if chains.is_empty() {
                            continue;
                        }
                        // if there is at least one valid chain, remember the current interface as active
                        active_filter.insert(i.to_owned(), chains.clone());
                        println!("{:?}", active_filter);
                        for chain in chains {
                            let i2 = "-i ".to_owned() + &i + " -j NFQUEUE --queue-num 0 --queue-bypass";
                            match ipt.append("filter", &chain, &i2) {
                                Ok(_) => println!("iptables rule inserted successfully"),
                                Err(e) => {
                                    println!("an error occurred while inserting iptables rule: {}", e);
                                    exit(1)
                                }
                            }
                        }
                    }
                    if active_filter.is_empty() {
                        eprintln!("no valid interface-chain pair was specified, terminating");
                        exit(1);
                    }
                }
            }
            _ => (),
        }

        println!("iptables config done");


        // load default action from config file
        let mut default_action = Verdict::Accept;
        if let Some(drop) = docs["drop_by_default"].as_bool() {
            if drop {
                default_action = Verdict::Drop;
            }
        }

        // create shared linked list for storing rules
        let rw_rules = Arc::new(RwLock::new(list_rule_manager::ListRuleManager::new(default_action)));
        let rules_1 = thread_safe_wrapper::ThreadSafeRead::new(Arc::clone(&rw_rules));


        // start threads
        let term_1 = thread_safe_wrapper::ThreadSafeRead::new(Arc::clone(&term));
        let cmd_processor = thread::spawn(move || Self::socket_thread(term_1, rw_rules));
        let term_2 = thread_safe_wrapper::ThreadSafeRead::new(Arc::clone(&term));
        let queue_processor = thread::spawn(move || Self::queue_thread(term_2, rules_1));

        // graceful shutdown
        match queue_processor.join() {
            Ok(_) => println!("queue processing thread finished"),
            Err(e) => println!("an error occurred while ending the queue processing thread: {:?}", e)
        }
        println!("finishing");
        match docs["manage_iptables"].as_bool() {
            Some(manage) => {
                for iface in active_filter.keys() {
                    for chain in active_filter.get(iface).unwrap() {
                        match ipt.delete("filter", chain, &("-i ".to_owned() + iface + " -j NFQUEUE --queue-num 0 --queue-bypass")) { // TODO: make this part into function, that can be called in case of catastrophe
                            Ok(_) => println!("done"),
                            Err(e) => println!("an error occurred while disconnecting from iptables: {}", e)
                        }
                    }
                }
            }
            _ => ()
        }

        // opens and closes connection to unix socket so the while loop is always terminated gracefully
        let mut stream: UnixStream;
        match UnixStream::connect("/tmp/fw.sock") {
            Ok(sock) => stream = sock,
            Err(msg) => {
                eprintln!("an error occurred while connecting to the unix socket: {}", msg);
                exit(1)
            }
        }
        match stream.write(b"end\n") {
            Ok(_) => (),
            Err(err) => println!("{}", err)
        }
        match stream.shutdown(Shutdown::Both) {
            Ok(_) => (),
            Err(e) => println!("an error occurred while shutting down the socket: {}", e)
        }
        match cmd_processor.join() {
            Ok(_) => println!("command processing thread finished"),
            Err(e) => println!("an error occurred while ending the command processing thread: {:?}", e)
        }

        println!("ending main thread");
        Ok(())
    }
}

fn main() {
    match Daemon::run_filter() {
        Ok(()) => println!("Successfully ended."),
        Err(e) => println!("Error: {}", e)
    }
}

/* multi-threading version*/

use nfq::{Queue, Verdict};
use signal_hook::low_level::exit;
use std::process;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::os::unix::net::{UnixListener,UnixStream};
use std::net::Shutdown;
use std::io::Read;
use std::sync::{Arc, RwLock};
mod thread_safe_wrapper;
mod packet_struct;


// enums for L3 and L4 header indexing
enum PacketField {
    VERSION = 0,
    ProtocolV4 = 9,
    SrcAddrV4 = 12,
    DstAddrV4 = 16
}

enum L4fields {
    SrcPort = 0,
    DstPort = 2
}

// helper functions for pakcet parsing

#[allow(dead_code)]
fn process_icmp_packet() {
    // twe can filter based on different message types such as echo, echo reply, ...
}

fn process_ipv4_packet(packet: &[u8], info: &mut packet_struct::PacketInfo) {
    // the src and dst ipv4 addresses are prepared as 4 byte slices and converted to 32 bit integers (easy masking) for matching  
    let src_slice = &packet[PacketField::SrcAddrV4 as usize .. PacketField::SrcAddrV4 as usize + 4];
    let dst_slice = &packet[PacketField::DstAddrV4 as usize .. PacketField::DstAddrV4 as usize + 4];

    let mut src: [u8; 4] = [0; 4];
    src.clone_from_slice(src_slice);

    let mut dst: [u8; 4] = [0; 4];
    dst.clone_from_slice(dst_slice);

    info.src_addr = u32::from_le_bytes(src);
    info.dst_addr = u32::from_le_bytes(dst);

    println!("{:?}, {:?}", src, dst);

    // calaculation of the header size, so we pass only the payload to the next function
    let header_size = ((packet[0] & 0b00001111) * 4) as usize;

    match &packet[PacketField::ProtocolV4 as usize] {
        // maybe add option to ban specific protocols
        //1 => process_icmp_packet(),
        6 => {info.l4protocol = packet_struct::L4protocols::TCP;
            process_tcp(&packet[header_size..], info)},
        17 => {info.l4protocol = packet_struct::L4protocols::UDP;
            process_udp(&packet[header_size..], info)},
        _ => println!("received an unknown encapsulated protocol.")
    }
}

#[allow(unused_variables)]
fn process_ipv6_packet(packet: &[u8], info: &mut packet_struct::PacketInfo) {
    // todo: dual stack support
}

fn process_tcp(packet: &[u8], info: &mut packet_struct::PacketInfo) {
    let src_port = &packet[L4fields::SrcPort as usize..L4fields::SrcPort as usize + 2];
    let dst_port = &packet[L4fields::DstPort as usize..L4fields::DstPort as usize + 2];

    info.src_port = ((src_port[0] as u16) << 8) | src_port[1] as u16;
    info.dst_port = ((dst_port[0] as u16) << 8) | dst_port[1] as u16;
}


// this is just temporary, the L4 protocols will get more features in the future
fn process_udp(packet: &[u8], info: &mut packet_struct::PacketInfo) {
    let src_port = &packet[L4fields::SrcPort as usize..L4fields::SrcPort as usize + 2];
    let dst_port = &packet[L4fields::DstPort as usize..L4fields::DstPort as usize + 2];

    info.src_port = ((src_port[0] as u16) << 8) | src_port[1] as u16;
    info.dst_port = ((dst_port[0] as u16) << 8) | dst_port[1] as u16;
}


// helper functions for rule management
// just a draft
fn parse_new_rule(rule: Vec<u8>) {
    if rule.is_empty() {
        return;
    }
    // find out the message type
    match rule[0] & 0b11000000 {
        0b00000000 => println!("msg_type 1"), // insert
        0b01000000 => println!("msg_type 2"), // remove
        0b10000000 => println!("msg_type 3"), // commit/save
        0b11000000 => println!("msg_type 4"), // free
        _ => println!("unknown message type")
    }
}


// fucntion, that will run in the unix socket thread - used for communication with user

fn socket_thread(pid: u32, term: thread_safe_wrapper::ThreadSafeRead<Arc<AtomicBool>>) -> std::io::Result<()> {

    let listener = match UnixListener::bind(format!("/tmp/{}.sock", pid)) {
        Err(_) => panic!("failed to bind socket"),
        Ok(stream) => stream,
    };
    while !term.read().load(Ordering::Relaxed){
        match listener.accept() {
            Ok((mut socket, addr)) => {
                println!("Got a client: {:?} - {:?}", socket, addr);
                let mut response = String::new();
                socket.read_to_string(&mut response).unwrap();
                //println!("received: {}", response);
                parse_new_rule(response.into_bytes());
                // socket.write(b"hello world").unwrap(); // maybe send an ACK
            }
            Err(e) => println!("accept function failed: {:?}", e),
        }
    }
    std::fs::remove_file(format!("/tmp/{}.sock", pid)).unwrap();
    println!("stopping loop");
    Ok(())
}

// fucntion, that will run in the nfqueue thread - used for processing packets from queue

fn queue_thread(term: thread_safe_wrapper::ThreadSafeRead<Arc<AtomicBool>>) {
    println!("starting");
    
    let mut queue = Queue::open().unwrap();
    queue.bind(0).unwrap();
    while !term.read().load(Ordering::Relaxed) {
        let mut msg = queue.recv().unwrap();
        let packet = msg.get_payload();
        let version = packet[PacketField::VERSION as usize];

        let mut packet_info = packet_struct::PacketInfo::new();

        match version & 0b11110000 {    // only the first four bits represent IP version, so we use a bitmask

            0b01000000 => {packet_info.version = packet_struct::IPversions::IPv4;
                process_ipv4_packet(packet, &mut packet_info)},  // 0100 0000 - the IP version is 4

            0b01100000 => {packet_info.version = packet_struct::IPversions::IPv6;
                process_ipv6_packet(packet, &mut packet_info)},  // 0110 0000 - the IP version is 6

            _ => println!("received unknown IP version packet.")
        }
        // now we have all the information needed to check the packet against the rules

        // placeholder rule, which drops all packets destined for port 22/TCP
        let rule = packet_struct::Rule::new(
            false,
            packet_struct::IPversions::IPv4,
            0b0, // -> 0.0.0.0
            0,
            0b0,
            0,
            packet_struct::L4protocols::TCP,
            0,
            22
        );

        if rule.check_packet(&mut packet_info) {
            if rule.get_permit() {
                //msg.set_verdict(Verdict::Accept);
                packet_info.verdict = packet_struct::PacketVerdict::Accept;
            } else {
                //msg.set_verdict(Verdict::Drop);
                packet_info.verdict = packet_struct::PacketVerdict::Drop;
            }
        }
        println!("{:?}", packet_info);
        // this will be set inside the condition above
        msg.set_verdict(Verdict::Accept);
        queue.verdict(msg).unwrap();
    }    
    println!("stopping loop");
}


// this function initiates the iptables queue, both threads and SIGTERM hook
// after SIGTERM is issued, performs graceful shutdown

fn run_filter() -> Result<(), std::io::Error> {
    
    let ipt = iptables::new(false).unwrap();
    match ipt.append("filter", "INPUT", "-i enp1s0 -j NFQUEUE --queue-num 0") {
        Ok(_) => println!("iptables rule inserted successfully"),
        Err(e)=> {println!("an error occured while inserting iptables rule: {}", e); exit(1)}
    }
    
    let term_rw = Arc::new(AtomicBool::new(false));


    signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&term_rw)).unwrap();
    let term = Arc::new(RwLock::new(term_rw));


    let term_1 = thread_safe_wrapper::ThreadSafeRead::new(Arc::clone(&term));
    let cmd_processor = thread::spawn(move || socket_thread(process::id(), term_1));
    let term_2 = thread_safe_wrapper::ThreadSafeRead::new(Arc::clone(&term));
    let queue_processor = thread::spawn(move || queue_thread(term_2));

    match queue_processor.join() {
        Ok(_) => println!("queue processing thread finished"),
        Err(e) => println!("an error occured while ending the queue processing thread: {:?}", e)
    }
    println!("finishing");
    match ipt.delete("filter", "INPUT", "-i enp1s0 -j NFQUEUE --queue-num 0") {
        Ok(_) => println!("done"),
        Err(e) => println!("unexpected error occured while disconnecting from iptables: {}", e)
    }
    // opens and closes connection to unix socket so it the while loop is always terminated gracefully
    let stream = UnixStream::connect(format!("/tmp/{}.sock", process::id())).unwrap();
    match stream.shutdown(Shutdown::Both) {
        Ok(_) => (),
        Err(e) => println!("an error occured while shutting down the socket: {}", e)
    }
    match cmd_processor.join() {
        Ok(_) => println!("command processing thread finished"),
        Err(e) => println!("an error occured while ending the command processing thread: {:?}", e)
    }

    println!("ending main thread");
    Ok(())
}

fn main() {
    match run_filter() {
        Ok(()) => println!("Successfully ended."),
        Err(e) => println!("Error: {e:?}"),
    }
}

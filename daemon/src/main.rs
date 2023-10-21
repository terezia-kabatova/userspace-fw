/* multi-threading version*/

extern crate serde;
extern crate yaml_rust;

use rule_manager::rule_manager_trait::RuleManagerTrait;
use nfq::Queue;
use signal_hook::low_level::exit;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::os::unix::net::{UnixListener, UnixStream};
use std::net::Shutdown;
use std::io::{BufReader, BufRead, Write};
use std::fs::File;
use std::ops::Deref;
use shared::{Msg, Rule};
use std::sync::{Arc, RwLock, RwLockWriteGuard};
use nfq::Verdict::Accept;
use component_factory::real_component_factory;
use rule_manager::list_rule_manager;
use crate::list_rule_manager::ListRuleManager;
use crate::config_manager::ConfigManager;
use crate::packet_parser::PacketParser;
use crate::thread_safe_wrapper::ThreadSafeRead;

mod thread_safe_wrapper;
mod rule_manager;
mod config_manager;
mod packet_parser;
mod component_factory;


macro_rules! unwrap_or_return {
    ( $e:expr ) => {
        match $e {
            Ok(x) => x,
            Err(e) => return Err(format!("an error occurred: {}", e)),
        }
    }
}


pub struct Daemon{
}


impl Daemon {

    // helper functions for rule management
    fn deserialize_rule(parser_msg: &Msg) -> Result<Rule, String> {
        return match serde_json::from_str::<Rule>(&parser_msg.payload) {
            Ok(r) => Ok(r),
            Err(err_msg) => Err(format!("an error occurred during rule deserialization: {}", err_msg.to_string()))
        }
    }

    fn parse_new_rule(msg: Vec<u8>, mut rules: &mut Arc<RwLock<dyn RuleManagerTrait>>) -> Result<String, String> {
        if msg.is_empty() {
            return Err(String::from("Received message was empty."));
        }

        let mut response: String = String::from("success");

        let parser_msg: shared::Msg;
        match serde_json::from_slice(&msg[..]) {
            Ok(msg) => parser_msg = msg,
            Err(err_msg) => return Err(format!("an error occurred during deserialization: {}", err_msg.to_string()))
        }
        if matches!(parser_msg.action, shared::Action::Commit) {
            ConfigManager::save_fw_rules(rules.clone());
        }

        let mut write_rules = rules.write().unwrap();
        match parser_msg.action {
            shared::Action::Insert {idx} => {
                // get rule that will be inserted
                let rule = unwrap_or_return!(Self::deserialize_rule(&parser_msg));
                // get index, where the rule will be inserted
                let i;
                match idx {
                    Some(ind) => i = ind,
                    None => i = write_rules.get_rule_count()
                }
                // insert the rule
                match write_rules.add_rule_at(i, rule) {
                    Ok(_) => (),
                    Err(err_msg) => return Err(format!("an error occurred during rule insertion: {}", err_msg.to_string()))
                }
            }

            shared::Action::Delete => {
                let rule = unwrap_or_return!(Self::deserialize_rule(&parser_msg));
                match write_rules.remove_rule(rule) {
                    Ok(_) => (),
                    Err(err_msg) => return Err(format!("an error occurred during rule deletion: {}", err_msg))
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
                    Err(err_msg) => return Err(format!("an error occurred during rule deletion: {}", err_msg))
                }
            }

            shared::Action::List => {
                response = write_rules.show();
            }

            _ => ()
        }
        println!("{}", write_rules.show());
        Ok(response)
    }

    // function, that will run in the unix socket thread - used for communication with user
    fn socket_thread(term: ThreadSafeRead<Arc<AtomicBool>>, mut rules: Arc<RwLock<dyn RuleManagerTrait>>) -> std::io::Result<()> {
        // the socket may or may not be present
        match std::fs::remove_file("/tmp/fw.sock") {
            _ => ()
        }
        println!("starting socket thread");
        // initialize
        let listener = match UnixListener::bind("/tmp/fw.sock") {
            Err(_) => panic!("failed to bind socket"),
            Ok(stream) => stream,
        };

        // accept connections until SIGTERM is issued
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
                            match Self::parse_new_rule(response.into_bytes(), &mut rules) {
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

    fn queue_thread(term: ThreadSafeRead<Arc<AtomicBool>>, rules: Arc<RwLock<dyn RuleManagerTrait>>, mut packet_parser:  PacketParser, mut queue: Queue) {
        println!("starting queue thread");

        while !term.read().load(Ordering::Relaxed) {
            let mut msg;
            match queue.recv() {
                Ok(packet) => msg = packet,
                Err(err_msg) => {
                    eprintln!("an error occurred while receiving packet from queue: {}", err_msg);
                    continue;
                }
            }

            // get packet contents and parse headers
            packet_parser.process_packet(msg.get_payload());

            // now we have all the information needed to check the packet against the rules
            let read_rules = rules.read().unwrap();
            let verdict = read_rules.check_packet(&mut packet_parser.get_packet_info());
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

    pub fn run_filter(queue: Queue, packet_parser: PacketParser, r: Arc<RwLock<dyn RuleManagerTrait>>, cfg_manager: &mut ConfigManager) -> Result<(), std::io::Error> {


        // create shared variable for terminating
        let term_rw = Arc::new(AtomicBool::new(false));

        match signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&term_rw)) {
            Ok(_) => (),
            Err(msg) => {
                eprintln!("an error occurred while registering signal hook: {}", msg);
                exit(1);
            }
        }

        let r1 = r.clone();
        let r2 = r.clone();

        // start thread for unix socket
        // rules in iptables are not configured yet, so in case of panic they are not left there
        let term_1 = ThreadSafeRead::new(Arc::clone(&term_rw));
        let cmd_processor = thread::spawn(move || Self::socket_thread(term_1, r1));


        cfg_manager.insert_ipt_rules().unwrap();

        println!("iptables config done");

        // start thread for nfqueue
        let term_2 = ThreadSafeRead::new(Arc::clone(&term_rw));
        let queue_processor = thread::spawn(move || Self::queue_thread(term_2, r2, packet_parser, queue));

        // graceful shutdown
        match queue_processor.join() {
            Ok(_) => println!("queue processing thread finished"),
            Err(e) => println!("an error occurred while ending the queue processing thread: {:?}", e)
        }
        println!("finishing");

        cfg_manager.remove_ipt_rules().unwrap();

        stop_cmd_thread(cmd_processor);

        println!("ending main thread");
        Ok(())
    }
}



fn stop_cmd_thread(cmd_processor: thread::JoinHandle<Result<(), std::io::Error>>) {
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
}

fn main() {
    let mut factory_result = real_component_factory::RealComponentFactory::new();
    let mut factory;
    match factory_result {
        Ok(f) => factory = f,
        Err(e) => {
            println!("Error: {}", e);
            exit(1);
        }
    }
    match Daemon::run_filter(factory.get_queue(), factory.get_packet_parser(), factory.get_rule_manager(), factory.get_config_manager()) {
        Ok(()) => println!("Successfully ended."),
        Err(e) => println!("Error: {}", e)
    }
}

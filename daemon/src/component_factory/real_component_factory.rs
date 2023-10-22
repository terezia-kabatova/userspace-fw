use std::fs::read;
use std::process::exit;
use std::sync::{Arc, RwLock};
use crate::{ListRuleManager, RuleManagerTrait};
use crate::ConfigManager;
use crate::PacketParser;
use nfq::Queue;
use nfq::Verdict::Accept;
use crate::thread_safe_wrapper;
use super::component_factory_trait::ComponentFactoryTrait;

pub struct RealComponentFactory {
    cfg_manager: ConfigManager
}

impl RealComponentFactory {
    pub fn new() -> Result<Box<dyn ComponentFactoryTrait>, String> {
        let cfg_manager = ConfigManager::new();
        match cfg_manager {
            Ok(cfg) => return Ok(Box::new(RealComponentFactory { cfg_manager: cfg })),
            Err(err_msg) => return Err(err_msg)
        }
    }
}

impl ComponentFactoryTrait for RealComponentFactory {
    fn get_queue(&self) -> Queue {
        let mut queue: Queue;
        match Queue::open() {
            Ok(q) => queue = q,
            Err(err_msg) => {
                eprintln!("an error occurred while opening queue: {}", err_msg);
                exit(1);
            }
        }
        match queue.bind(0) {
            Ok(_) => (),
            Err(err_msg) => {
                eprintln!("an error occurred while binding to queue: {}", err_msg);
                exit(1);
            }
        }
        return queue;
    }

    fn get_config_manager(&mut self) -> &mut ConfigManager {
        return &mut self.cfg_manager;
    }

    fn get_packet_parser(&mut self) -> PacketParser {
        return PacketParser::new();
    }

    fn get_rule_manager(&mut self) -> Arc<RwLock<dyn RuleManagerTrait>> {
        let mut rules = Arc::new(RwLock::new(ListRuleManager::new(Accept))) as Arc<RwLock<dyn RuleManagerTrait>>;
        rules.write().unwrap().set_default_action(self.cfg_manager.get_default_action()).unwrap();
        match ConfigManager::load_fw_rules(&mut rules) {
            Ok(_) => (),
            Err(err) => println!("could not load rules from config file: {}", err)
        }
        return rules;
    }
}
use std::sync::{Arc, RwLock};
use crate::RuleManagerTrait;
use crate::ConfigManager;
use crate::PacketParser;
use nfq::Queue;

pub trait ComponentFactoryTrait {
    fn get_queue(&self) -> Queue;
    fn get_config_manager(&mut self) -> &mut ConfigManager;
    fn get_packet_parser(&mut self) -> PacketParser;
    fn get_rule_manager(&mut self) -> Arc<RwLock<dyn RuleManagerTrait>>;
}
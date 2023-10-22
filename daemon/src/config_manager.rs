extern crate yaml_rust;

use yaml_rust::YamlLoader;
use nfq::Verdict;
use std::fs::File;
use std::io::Write;
use std::fs;
use network_interface::{NetworkInterface, NetworkInterfaceConfig};
use std::collections::HashMap;
use std::path::Iter;
use std::ptr::read;
use std::sync::{Arc, RwLock, RwLockWriteGuard};
use iptables::new;
use serde_json::map::Keys;
use crate::RuleManagerTrait;


pub struct ConfigManager {
    active_filter: Vec<(String, String)>,
    default_action: Verdict,
    ipt: Option<iptables::IPTables>
}


impl ConfigManager {
    pub fn new() -> Result<ConfigManager, String> {
        // load config file
        let config: String;
        match fs::read_to_string("/etc/usfw/fw.yaml") {
            Ok(cfg) => config = cfg,
            Err(msg) => {
                return Err(format!("an error occurred while reading config file: {}", msg));
            }
        }
        let docs;
        // parse config file
        match YamlLoader::load_from_str(&config) {
            Ok(y) => docs = y[0].clone(),
            Err(msg) => {
                return Err(format!("an error occurred while parsing config file: {}", msg));
            }
        }

        // load default action from config file
        let mut default_action = Verdict::Accept;
        if let Some(drop) = docs["drop_by_default"].as_bool() {
            if drop {
                default_action = Verdict::Drop;
            }
        }

        // maps interfaces and chains that should be filtered
        let mut active_filter: Vec<(String, String)> = Vec::new();

        let mut ipt= None;

        match docs["manage_iptables"].as_bool() {
            Some(manage) => {

                // the daemon will manage the iptables rules
                if manage {

                    // initialize iptables object
                    match iptables::new(false) {
                        Ok(iptables) => ipt = Some(iptables),
                        Err(msg) => {
                            return Err(format!("an error occurred while initiating iptables object: {}", msg));

                        }
                    }

                    // get the list of interfaces specified in config file (filter section)
                    let configured_ifaces;
                    match docs["filter"].as_hash() {
                        Some(ifcs) => configured_ifaces = ifcs,
                        None => {
                            return Err(format!("manage_iptables is true, but could not read filter section"));
                        }
                    }

                    // get list of all interfaces on host
                    let valid_ifaces = NetworkInterface::show().unwrap().iter().map(|i| i.name.clone()).collect::<Vec<String>>();

                    // find all valid interface specifications
                    let valid_ifaces: Vec<String> = configured_ifaces.keys().into_iter()
                        .map(|i| String::from(i.as_str().unwrap()))
                        .filter(|i| valid_ifaces.contains(&i))
                        .collect();
                    if valid_ifaces.is_empty() {
                        return Err(format!("at least one valid interface should be specified when manage_iptables option is true"));
                    }

                    // specify valid chains
                    let valid_chains = ["INPUT", "OUTPUT", "FORWARD"];

                    // get all valid chain specifications from config file (per interface)
                    for iface in configured_ifaces.keys() {
                        let i;
                        match iface.as_str() {
                            Some(x) => i = x,
                            None => {
                                eprintln!("could not read interface from config file");
                                continue;
                            }
                        }

                        let chains = configured_ifaces[iface].as_vec().unwrap().iter()
                            .map(|i| i.as_str().unwrap().to_uppercase())
                            .filter(|i| valid_chains.contains(&i.as_str()))
                            .collect::<Vec<String>>();


                        if chains.is_empty() {
                            continue;
                        }
                        // if there is at least one valid chain, remember the current interface as active
                        for chain in chains {
                            active_filter.push((i.to_owned(), chain.clone()));
                        }
                        //active_filter.append((i.to_owned(), chains.clone()));
                        println!("{:?}", active_filter);
                    }
                    if active_filter.is_empty() {
                        return Err(format!("no valid interface-chain pair was specified, terminating"));
                    }
                }
            }
            None => ()
        }

        // return the constructed config parser
        Ok(ConfigManager {active_filter: active_filter, default_action, ipt})
    }

    pub fn get_default_action(&mut self) -> nfq::Verdict {
        return self.default_action;
    }


    pub fn insert_ipt_rules(&mut self) -> Result<(), String> {
        match &self.ipt {
            Some(ipt) => {
                for (k, v) in &self.active_filter {
                    match ipt.append("filter", v, &("-i ".to_owned() + k + " -j NFQUEUE --queue-num 0 --queue-bypass")) {
                        Ok(_) => println!("iptables rule inserted successfully"),
                        Err(e) => {
                            return Err(format!("an error occurred while inserting iptables rule: {}", e));
                        }
                    }
                }
            }
            None => ()
        }
        Ok(())
    }

    pub fn remove_ipt_rules(&mut self) -> Result<(), String> {
        match &self.ipt {
            Some(ipt) => {
                for (k, v) in &self.active_filter {
                    match ipt.delete("filter", v, &("-i ".to_owned() + k + " -j NFQUEUE --queue-num 0 --queue-bypass")) {
                        Ok(_) => println!("iptables rule removed successfully"),
                        Err(e) => {
                            return Err(format!("an error occurred while inserting iptables rule: {}", e));
                        }
                    }
                }
            }
            None => ()
        }
        Ok(())
    }

    // loads saved rules into the rule manager
    pub fn load_fw_rules(rules: &mut Arc<RwLock<dyn RuleManagerTrait>>) -> Result<(), String> {
        match fs::read("/etc/usfw/rules.conf") {
            Ok(rule_cfg) => {
                let cfg_rules: Vec<shared::Rule>;
                match serde_json::from_slice(&rule_cfg) {
                    Ok(rules) => cfg_rules = rules,
                    Err(err) => return Err(format!("The rules in config file do not have correct format."))
                }
                let mut rw_rules = rules.write().unwrap();
                for rule in cfg_rules.iter() {
                    let idx = rw_rules.get_rule_count();
                    match rw_rules.add_rule_at(idx, rule.clone()) {
                        Ok(_) => (),
                        Err(err_msg) => return Err(format!("Rule {} was not inserted successfuly: {}", rule.to_string(), err_msg)),
                    }
                }
            },
            Err(_) => return Err(format!("Could not open rule configuration file, starting with empty ruleset.")),
        }
        return Ok(());
    }

    pub fn save_fw_rules(rules: Arc<RwLock<dyn RuleManagerTrait>>) -> Result<(), String> {
        match File::create("/etc/usfw/rules.conf") {
            Ok(mut rule_cfg) => {
                let r_rules = rules.read().unwrap();
                match rule_cfg.write(&r_rules.show().into_bytes()) {
                    Ok(_) => (),
                    Err(err_msg) => return Err(format!("Could not write to rule configuration file: {}", err_msg.to_string()))
                }
            },
            Err(err_msg) => return Err(format!("Could not open rule configuration file: {}", err_msg.to_string()))
        }
        Ok(())
    }
}
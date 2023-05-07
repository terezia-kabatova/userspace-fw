/*
the data structure for storing rules
will be instantiated in the main() in daemon/main.rs and sent to the threads
*/


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
    fn add_rule(&mut self, rule: shared::Rule) -> Result<(), String> {
        self.rules.push(rule);
        Ok(())
    }

    fn add_rule_at(&mut self, idx: usize, rule: shared::Rule) -> Result<(), String> {
        if idx >= self.rules.len() {
            return Err("index out of bounds".to_string());
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
}
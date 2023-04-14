/*
the data structure for storing rules
will be instantiated in the main() in daemon/main.rs and sent to the threads
*/

pub mod rule_manager_trait;
use self::rule_manager_trait::RuleManagerTrait;


// tree structure to be implemented
#[derive(Debug)]
pub struct TreeRuleManager  {
    rules: Vec<shared::Rule>
}
impl TreeRuleManager {
    pub fn new() -> TreeRuleManager {
        TreeRuleManager { rules: Vec::new() }
    }
}

impl RuleManagerTrait for TreeRuleManager {
    fn add_rule(&mut self, rule: shared::Rule) -> Result<(), String> {
        Ok(())
    }

    fn remove_rule(&mut self, rule: shared::Rule) -> Result<(), String> {
        Ok(())
    }

    fn remove_rule_num(&mut self, rule: usize) -> Result<(), String> {
        Ok(())
    }

    fn check_packet(&self, packet: &mut shared::PacketInfo) -> nfq::Verdict {
        nfq::Verdict::Accept
    }

    fn show(&self) -> String {
        String::new()
    }
}

// standard list implementation
pub struct ListRuleManager  {
    rules: Vec<shared::Rule>,
    default_verdict: nfq::Verdict
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

    fn remove_rule(&mut self, rule: shared::Rule) -> Result<(), String> {
        self.rules.retain(|rul| rul != &rule);
        Ok(())
    }

    fn remove_rule_num(&mut self, rule: usize) -> Result<(), String> {
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
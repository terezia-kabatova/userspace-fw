use nfq::Verdict;

pub trait RuleManagerTrait: Sync + Send {
    // fn add_rule(&mut self, rule: shared::Rule) -> Result<(), String>;
    fn get_rule_count(&self) -> usize;
    fn add_rule_at(&mut self, idx: usize, rule: shared::Rule) -> Result<(), String>;
    fn remove_rule(&mut self, rule: shared::Rule) -> Result<(), String>;
    fn remove_rule_num(&mut self, rule: usize) -> Result<(), String>;
    fn check_packet(&self, packet: &mut shared::PacketInfo) -> nfq::Verdict;
    fn show(&self) -> String;
    fn set_default_action(&mut self, verdict: Verdict) -> Result<(), String>;
}

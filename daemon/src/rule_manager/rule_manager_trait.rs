pub trait RuleManagerTrait {
    fn add_rule(&mut self, rule: shared::Rule) -> Result<(), String>;
    fn remove_rule(&mut self, rule: shared::Rule) -> Result<(), String>;
    fn check_packet(&self, packet: &mut shared::PacketInfo) -> nfq::Verdict;
    fn show(&self) -> String;
}

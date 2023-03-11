pub trait IPtablesManagerTrait {
    fn connect_to_iface(iface_name: String) -> std::Result<(), String>;
    fn disconnect_from_iface(iface_name: String) -> std::Result<(), String>;
}
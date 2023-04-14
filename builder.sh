cargo build
chcon system_u:object_r:bin_t:s0 target/debug/daemon

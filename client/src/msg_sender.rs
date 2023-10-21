use std::{os::unix::net::UnixStream, io::{Write, Read}};


pub struct MsgSender {}


impl MsgSender {
    pub fn send_to_daemon(message: shared::Msg) -> String {
        // connect to daemon socket
        let mut response: String = String::new();
        let mut stream = match UnixStream::connect("/tmp/fw.sock") {
            Ok(it) => it,
            Err(err) => {
                println!("{}", err);
                return String::from("Could not connect to the socket");
            }
        };

        // serialize the new rule and send through the socket
        let v = serde_json::to_value(message).unwrap().to_string() + "\n";
        match stream.write_all(&v.into_bytes()) {
            Ok(it) => it,
            Err(_err) => return String::from("Could not write to the socket"),
        };

        // receive response from daemon
        match stream.read_to_string(&mut response) {
            Ok(_) => {
                return response;
            }
            Err(e) => {
                return format!("Failed to receive data: {}", e);
            }
        }
    }
}
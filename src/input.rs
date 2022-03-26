use coarsetime::Instant;
use crossbeam_channel::{Receiver, Sender};
use std::borrow::Cow;
use std::io::Read;
use std::net::TcpListener;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use usiem::components::command::SiemCommandCall;
use usiem::components::common::{
    SiemComponentCapabilities, SiemComponentStateStorage, SiemMessage,
};
use usiem::components::SiemComponent;
use usiem::events::SiemLog;

#[derive(Clone)]
pub struct SyslogInput {
    name : String,
    host: Cow<'static, str>,
    local_sender: Sender<SiemMessage>,
    local_receiver: Receiver<SiemMessage>,
    log_sender: Sender<SiemLog>,
    log_receiver: Receiver<SiemLog>,
    kernel_sender: Sender<SiemMessage>,
    id: u64,
}

impl SiemComponent for SyslogInput {
    fn name(&self) -> &str {
        &self.name
    }

    fn set_log_channel(&mut self, sender: Sender<SiemLog>, receiver: Receiver<SiemLog>) {
        self.log_sender = sender;
        self.log_receiver = receiver;
    }

    fn local_channel(&self) -> Sender<SiemMessage> {
        self.local_sender.clone()
    }

    fn set_kernel_sender(&mut self, sender: Sender<SiemMessage>) {
        self.kernel_sender = sender;
    }

    fn capabilities(&self) -> SiemComponentCapabilities {
        return SiemComponentCapabilities::new(
            Cow::Borrowed("SyslogInput"),
            Cow::Borrowed("Syslog input"),
            Cow::Borrowed(""),
            vec![],
            vec![],
            vec![],
            vec![],
        );
    }

    fn run(&mut self) {
        let listener = match TcpListener::bind(&self.host[..]) {
            Ok(v) => v,
            Err(_) => {
                format!("Cannot start TCP syslog listener on port: {}", self.host);
                return;
            }
        };
        let _a = listener.set_nonblocking(true);
        let listen = Arc::from(AtomicBool::new(true));

        let listen_spawner = Arc::clone(&listen);

        let local_receiver = self.local_receiver.clone();
        let log_sender = self.log_sender.clone();
        let kernel_sender = self.kernel_sender.clone();
        let mut updater_counter = 0;
        loop {
            if !listen_spawner.load(Ordering::Relaxed) {
                return;
            }

            match listener.accept() {
                Ok((mut stream, socket)) => {
                    let listen_spawner = Arc::clone(&listen);
                    Instant::update();
                    let log_sender = log_sender.clone();
                    //This comp does not send info to the kernel
                    let _kernel_sender = kernel_sender.clone();
                    thread::spawn(move || {
                        let mut buffer = [0; 9192];
                        let origin = format!("{}", socket);
                        let mut last_string = String::with_capacity(4096);
                        loop {
                            let result = stream.read(&mut buffer);
                            let message_size = match result {
                                Ok(message) => message,
                                Err(_error) => {
                                    return;
                                }
                            };
                            if message_size == 0 {
                                //thread::sleep_ms(100);
                                return;
                            }
                            if !listen_spawner.load(Ordering::Relaxed) {
                                return;
                            }

                            let buffer_lines =
                                match String::from_utf8(buffer[0..message_size].to_vec()) {
                                    Ok(v) => v,
                                    Err(_) => {
                                        return;
                                    }
                                };
                            last_string.push_str(&buffer_lines);
                            let mut last_pos = 0;
                            loop {
                                let pos = match last_string[last_pos..].find("\n") {
                                    Some(pos) => pos,
                                    None => {
                                        break;
                                    }
                                };
                                let msg = (&last_string[last_pos..last_pos + pos]).to_string();
                                let mut log = SiemLog::new(
                                    msg,
                                    Instant::recent().as_u64() as i64,
                                    origin.clone(),
                                );
                                loop {
                                    //TODO: Parse syslog header
                                    match log_sender.send(log) {
                                        Ok(_) => {
                                            break;
                                        }
                                        Err(e) => {
                                            log = e.0;
                                        }
                                    }
                                }
                                last_pos += pos + 1;
                            }
                            if last_pos < last_string.len() {
                                last_string = String::from(&last_string[last_pos..]);
                            } else {
                                last_string = String::new();
                            }
                        }
                    });
                }
                Err(e) => {
                    match e.kind() {
                        std::io::ErrorKind::WouldBlock => {
                            updater_counter += 1;
                            if updater_counter > 10 {
                                updater_counter = 0;
                                Instant::update();
                            }
                            match local_receiver.try_recv() {
                                Ok(msg) => match msg {
                                    SiemMessage::Command(_hdr, cmd) => match cmd {
                                        SiemCommandCall::STOP_COMPONENT(_) => {
                                            println!("STOPPING COMPONENT");
                                            (*listen_spawner).store(false, Ordering::Relaxed);
                                            return;
                                        }
                                        _ => {}
                                    },
                                    _ => {}
                                },
                                Err(_) => {}
                            }

                            //thread::sleep(std::time::Duration::from_millis(10));
                        }
                        _ => {
                            println!("Error in connection");
                            println!("{:?}", e);
                            // Notify kernel of error
                            //kernel_sender.send();

                            return;
                        }
                    }
                }
            };
        }
    }

    fn set_id(&mut self, id: u64) {
        self.id = id;
    }

    fn duplicate(&self) -> Box<dyn SiemComponent> {
        Box::new(self.clone())
    }

    fn set_datasets(&mut self, _datasets: Vec<usiem::components::dataset::SiemDataset>) {
        //Not required
    }

    fn set_storage(&mut self, _conn: Box<dyn SiemComponentStateStorage>) {
        //Not required
    }
}

impl SyslogInput {
    pub fn new(host: Cow<'static, str>) -> SyslogInput {
        let (local_sender, local_receiver) = crossbeam_channel::bounded(1000);
        let (log_sender, log_receiver) = crossbeam_channel::bounded(1000);
        let (kernel_sender, _kernel_receiver) = crossbeam_channel::bounded(1);
        let name = format!("SyslogInput:{}", &host);
        SyslogInput {
            host,
            local_sender,
            local_receiver,
            log_sender,
            log_receiver,
            kernel_sender,
            id: 0,
            name
        }
    }
}

#[cfg(test)]
mod tests {
    use usiem::components::command::SiemCommandHeader;

    use super::*;
    use std::io::Write;
    use std::thread;
    #[test]
    fn test_syslog() {
        let mut sys_input = SyslogInput::new(Cow::Borrowed("localhost:13333"));
        let (log_sender, log_receiver) = crossbeam_channel::bounded(1000);
        sys_input.set_log_channel(log_sender, log_receiver.clone());
        let local_sender = sys_input.local_channel();

        thread::spawn(move || {
            sys_input.run();
        });

        thread::spawn(move || {
            thread::sleep(std::time::Duration::from_millis(1000));
            let _sended = local_sender.send(SiemMessage::Command(
                SiemCommandHeader {
                    comm_id: 0,
                    comp_id: 0,
                    user: "KERNEL".to_string(),
                },
                SiemCommandCall::STOP_COMPONENT("ComponentToStop".to_string()),
            ));
        });
        thread::sleep(std::time::Duration::from_millis(10));

        let mut stream =
            std::net::TcpStream::connect("localhost:13333").expect("Must connect to localhost");
        let _writed = stream
            .write(b"This is the first log\nThis is the second log\n")
            .expect("Must send logs");
        match stream.flush() {
            Ok(_) => {}
            Err(e) => {
                println!("{}", e);
            }
        };
        thread::sleep(std::time::Duration::from_millis(50));
        let log1 = log_receiver.recv().expect("Must receive first log");
        assert_eq!(log1.message(), "This is the first log");
        let log2 = log_receiver.recv().expect("Must receive second log");
        assert_eq!(log2.message(), "This is the second log");
    }
}

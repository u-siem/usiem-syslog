use coarsetime::Instant;
use usiem::crossbeam_channel::{self, Receiver, Sender};
use usiem::{error, info};
use usiem::prelude::{SiemComponentStateStorage, SiemError};
use usiem::prelude::dataset::holder::DatasetHolder;
use std::borrow::Cow;
use std::collections::LinkedList;
use std::io::Read;
use std::net::TcpListener;


use usiem::components::command::SiemCommandCall;
use usiem::components::common::{
    SiemComponentCapabilities, SiemMessage,
};
use usiem::components::SiemComponent;
use usiem::events::SiemLog;

#[cfg(feature="metrics")]
use crate::metrics::{SyslogMetrics, generate_syslog_input_metrics};
#[cfg(feature="metrics")]
use usiem::components::metrics::SiemMetricDefinition;

#[derive(Clone)]
pub struct SyslogInput {
    host: Cow<'static, str>,
    local_sender: Sender<SiemMessage>,
    local_receiver: Receiver<SiemMessage>,
    log_sender: Sender<SiemLog>,
    log_receiver: Receiver<SiemLog>,
    datasets : DatasetHolder,
    #[cfg(feature="metrics")]
    metrics: (Vec<SiemMetricDefinition>, SyslogMetrics),
}

impl SiemComponent for SyslogInput {
    fn name(&self) -> &'static str {
        "SyslogInput"
    }

    fn set_log_channel(&mut self, sender: Sender<SiemLog>, receiver: Receiver<SiemLog>) {
        self.log_sender = sender;
        self.log_receiver = receiver;
    }

    fn local_channel(&self) -> Sender<SiemMessage> {
        self.local_sender.clone()
    }

    fn capabilities(&self) -> SiemComponentCapabilities {
        return SiemComponentCapabilities::new(
            Cow::Borrowed("SyslogInput"),
            Cow::Borrowed("Syslog input"),
            Cow::Borrowed(""),
            vec![],
            vec![],
            vec![],
            self.metrics.0.clone(),
        );
    }

    fn run(&mut self) -> Result<(), SiemError> {
        let listener = match TcpListener::bind(&self.host[..]) {
            Ok(v) => v,
            Err(_) => {
                return Err(SiemError::Io(format!("Cannot start TCP syslog listener on port: {}", self.host)));
            }
        };
        if let Err(err) = listener.set_nonblocking(true) {
            return Err(SiemError::Io(format!("Cannot start TCP syslog listener. Error setting nonblocking: {}", err))); 
        }

        let local_receiver = self.local_receiver.clone();
        let log_sender = self.log_sender.clone();
        let mut listeners = LinkedList::new();
        let mut buffer = [0; 4096];
        let mut last_active_connections = 0;
        loop {
            Instant::update();
            match listener.accept(){
                Ok((stream, _socket)) => {
                    let _ = stream.set_nonblocking(true);
                    self.increase_total_connections_metric();
                    listeners.push_back((stream, Vec::with_capacity(1024)));
                },
                Err(e) => {
                    match e.kind() {
                        std::io::ErrorKind::WouldBlock => {
                            match local_receiver.try_recv() {
                                Ok(msg) => match msg {
                                    SiemMessage::Command(_hdr, cmd) => match cmd {
                                        SiemCommandCall::STOP_COMPONENT(_) => return Ok(()),
                                        _ => {}
                                    },
                                    _ => {}
                                },
                                Err(_) => {}
                            }
                        }
                        _ => {
                            info!("Error in connection: {:?}", e);
                            return Ok(());
                        }
                    }
                },
            }
            let n_listeners = listeners.len();
            for _ in 0..n_listeners {
                let (mut stream, mut text_log) = match listeners.pop_front() {
                    Some(v) => v,
                    None => break
                };
                let readed_bytes = match stream.read(&mut buffer) {
                    Ok(v) => v,
                    Err(err) => {
                        match err.kind() {
                            std::io::ErrorKind::WouldBlock => {
                                listeners.push_back((stream, text_log));
                                continue;
                            },
                            _ => continue
                        }
                    }
                };
                if readed_bytes == 0 {
                    continue
                }
                self.increase_received_bytes_metric(readed_bytes);
                let mut splited_buf = buffer[0..readed_bytes].split_inclusive(|&v| v == b'\n');
                loop {
                    let partial_buffer = match splited_buf.next() {
                        Some(v) => {
                            if v.len() > 0 && v[v.len() - 1] == b'\n' {
                               & v[0..v.len() - 1]
                            }else {
                                text_log.extend_from_slice(v);
                                break;
                            }
                        },
                        None => break
                    };
                    let log = if text_log.len() == 0 {
                        SiemLog::new(String::from_utf8_lossy(&partial_buffer), Instant::recent().as_u64() as i64, "Syslog")
                    }else {
                        text_log.extend_from_slice(&partial_buffer);
                        SiemLog::new(String::from_utf8_lossy(&text_log[0..text_log.len()]), Instant::recent().as_u64() as i64, "Syslog")
                    };
                    unsafe {
                        text_log.set_len(0);
                    }
                    if let Err(err) = log_sender.send(log) {
                        error!("Cannot process log: {}", usiem::serde_json::to_string(&err.0).unwrap_or_default());
                        break;
                    }
                    self.increase_received_logs_metric();
                }
                listeners.push_front((stream, text_log));

            };
            if last_active_connections != listeners.len() {
                last_active_connections = listeners.len();
                self.set_active_connections_metric(last_active_connections);
            }
        }
    }

    fn duplicate(&self) -> Box<dyn SiemComponent> {
        Box::new(self.clone())
    }

    fn set_datasets(&mut self, datasets: DatasetHolder) {
        self.datasets = datasets;
    }

    fn set_storage(&mut self, _conn: Box<dyn SiemComponentStateStorage>) {
        //Not required
    }
}

impl SyslogInput {
    pub fn new(host: &str, name : &str) -> SyslogInput {
        let (local_sender, local_receiver) = crossbeam_channel::bounded(1000);
        let (log_sender, log_receiver) = crossbeam_channel::bounded(1000);
        SyslogInput {
            host : Cow::Owned(host.into()),
            local_sender,
            local_receiver,
            log_sender,
            log_receiver,
            datasets : DatasetHolder::new(),
            #[cfg(feature="metrics")]
            metrics : generate_syslog_input_metrics(name)
        }
    }
    fn increase_received_logs_metric(&self) {
        #[cfg(feature="metrics")]
        self.metrics.1.received_logs.inc();
    }
    fn increase_total_connections_metric(&self) {
        #[cfg(feature="metrics")]
        self.metrics.1.total_connections.inc();
    }
    fn increase_received_bytes_metric(&self, bytes : usize) {
        #[cfg(feature="metrics")]
        self.metrics.1.received_bytes.inc_by(bytes as i64);
    }
    fn set_active_connections_metric(&self, connections : usize) {
        #[cfg(feature="metrics")]
        self.metrics.1.active_connections.set(connections as f64);
    }
}

#[cfg(test)]
mod tst {
    use usiem::components::command::SiemCommandHeader;
    use super::*;
    use std::io::Write;
    use std::thread;
    use crate::testing::*;

    #[test]
    fn syslog_component_should_receive_logs() {
        let mut sys_input = SyslogInput::new(TCP_LISTENING_HOST, SYSLOG_COMPONENT_NAME);
        let (log_sender, log_receiver) = crossbeam_channel::bounded(1000);
        sys_input.set_log_channel(log_sender, log_receiver.clone());
        let local_sender = sys_input.local_channel();
        let capabilities = sys_input.capabilities();

        thread::spawn(move || {
            init_logging();
            let _ = sys_input.run();
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
        let mut total_sent = 0;
        let mut stream =
            std::net::TcpStream::connect(TCP_LISTENING_HOST).expect("Must connect to localhost");
        total_sent += stream
            .write(b"This is the first log\nThis is the second log\nThis is the third log")
            .expect("Must send logs");
        stream.flush().unwrap();
        thread::sleep(std::time::Duration::from_millis(500));// TODO: When standarized TCP KeepAlive for sockets add more than 1 second (Default in windows)
        total_sent += stream
            .write(b" with extra\n")
            .expect("Must send logs");
        stream.flush().unwrap();
        thread::sleep(std::time::Duration::from_millis(200));
        let log = log_receiver.recv().expect("Must receive first log");
        assert_eq!(log.message(), "This is the first log");
        let log = log_receiver.recv().expect("Must receive second log");
        assert_eq!(log.message(), "This is the second log");
        let log = log_receiver.recv().expect("Must receive second log");
        assert_eq!(log.message(), "This is the third log with extra");
        metrics_shold_match(capabilities.metrics(), 3, total_sent, 1, 1);
        drop(stream);
        thread::sleep(std::time::Duration::from_millis(100));
        metrics_shold_match(capabilities.metrics(), 3, total_sent, 1, 0);
    }
}

use coarsetime::Instant;
use rustls::server::Acceptor;
use rustls::{ServerConfig, ServerConnection};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use usiem::components::dataset::SiemDatasetType;
use usiem::components::dataset::text_map::TextMapSynDataset;
use usiem::components::storage::DummyStateStorage;
use usiem::crossbeam_channel::{self, Receiver, Sender};
use usiem::prelude::{SiemComponentStateStorage, SiemError};
use usiem::prelude::dataset::holder::DatasetHolder;
use std::borrow::Cow;
use std::collections::LinkedList;
use std::io::{Read, ErrorKind};
use std::net::TcpListener;
use std::sync::Arc;


use usiem::components::command::SiemCommandCall;
use usiem::components::common::{
    SiemComponentCapabilities, SiemMessage,
};
use usiem::components::SiemComponent;
use usiem::events::SiemLog;

use crate::common::read_log;
#[cfg(feature="metrics")]
use crate::metrics::{SyslogMetrics, generate_syslog_input_metrics};
#[cfg(feature="metrics")]
use usiem::components::metrics::SiemMetricDefinition;

pub const CERTIFICATE_FILENAME_CONFIGURATION : &str = "CERTIFICATE_FILENAME";
pub const PRIVATE_KEY_FILENAME_CONFIGURATION : &str = "PRIVATE_KEY_FILENAME";

#[derive(Clone)]
pub struct SyslogTlsInput {
    host: Cow<'static, str>,
    local_sender: Sender<SiemMessage>,
    local_receiver: Receiver<SiemMessage>,
    log_sender: Sender<SiemLog>,
    log_receiver: Receiver<SiemLog>,
    datasets : DatasetHolder,
    #[cfg(feature="metrics")]
    metrics: (Vec<SiemMetricDefinition>, SyslogMetrics),
    storage: Box<dyn SiemComponentStateStorage>
}

impl SiemComponent for SyslogTlsInput {
    fn name(&self) -> &'static str {
        "SyslogTlsInput"
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
            Cow::Borrowed("SyslogTlsInput"),
            Cow::Borrowed("Syslog input"),
            Cow::Borrowed(""),
            vec![],
            vec![],
            vec![],
            self.metrics.0.clone(),
        );
    }

    fn run(&mut self) -> Result<(), SiemError> {
        let (cert_filename, key_filename) = if let (Some(a), Some(b)) = (self.get_certificate_filename(), self.get_private_key_filename()) {
            (a, b)
        }else {
            return Err(SiemError::Configuration("Invalid certificate or key filename".into()));
        };
        let certs = self.load_certs(&cert_filename)?;
        let key = self.load_private_key(&key_filename)?;

        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(error)?;
        let server_config = Arc::new(server_config);
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
        let mut pending_connections = LinkedList::new();
        let mut accepted_connections: LinkedList<(ServerConnection, std::net::TcpStream, Vec<u8>)> = LinkedList::new();
        let mut buffer = [0; 4096];
        let mut last_active_connections = 0;
        loop {
            Instant::update();
            match listener.accept(){
                Ok((stream, _socket)) => {
                    let acceptor = Acceptor::default();
                    let _ = stream.set_nonblocking(true);
                    self.increase_total_connections_metric();
                    pending_connections.push_back((acceptor, stream));
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
                            usiem::info!("Error listening for connections: {:?}", e);
                            return Ok(());
                        }
                    }
                },
            }
            let n_listeners = pending_connections.len();
            for _ in 0..n_listeners {
                let (mut acceptor, mut stream) = match pending_connections.pop_front() {
                    Some(v) => v,
                    None => break
                };
                if let Err(err) = acceptor.read_tls(&mut stream) {
                    if let std::io::ErrorKind::WouldBlock = err.kind() {
                        pending_connections.push_back((acceptor, stream));
                        continue;
                    }
                    usiem::debug!("Cannot accept TLS request: {:?}", err);
                    continue
                }
                match acceptor.accept() {
                    Ok(None) => {},
                    Ok(Some(v)) => {
                        let conn = match v.into_connection(server_config.clone()) {
                            Ok(v) => v,
                            Err(err) => {
                                usiem::debug!("Cannot accept TLS request: {:?}", err);
                                continue
                            }
                        };
                        accepted_connections.push_back((conn, stream, Vec::with_capacity(4096)));
                        continue
                    },
                    Err(err) => {
                        usiem::debug!("Cannot accept TLS request: {:?}", err);
                        continue
                    }
                }
                pending_connections.push_front((acceptor, stream));

            };
            let n_connections = accepted_connections.len();
            for _ in 0..n_connections {
                let (mut connection, mut stream, mut text_log) = match accepted_connections.pop_front() {
                    Some(v) => v,
                    None => break
                };
                let mut tls_stream = rustls::Stream::new(&mut connection, &mut stream); 
                let readed = match tls_stream.read(&mut buffer) {
                    Ok(v) => v,
                    Err(err) => {
                        if let ErrorKind::WouldBlock = err.kind() {
                            accepted_connections.push_back((connection, stream, text_log));
                            continue;
                        }
                        continue
                    }
                };
                if readed == 0 {
                    continue;
                }
                self.increase_received_bytes_metric(readed);
                let sent = read_log(&buffer[0..readed], &mut text_log, &log_sender);
                self.increase_received_logs_metric_by(sent);
                accepted_connections.push_back((connection, stream, text_log));
            } 


            if last_active_connections != accepted_connections.len() {
                last_active_connections = accepted_connections.len();
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

    fn set_storage(&mut self, storage: Box<dyn SiemComponentStateStorage>) {
        //Not required
        self.storage = storage;
    }
}

impl SyslogTlsInput {
    pub fn new(host: &str, name : &str) -> SyslogTlsInput {
        let (local_sender, local_receiver) = crossbeam_channel::bounded(1000);
        let (log_sender, log_receiver) = crossbeam_channel::bounded(1000);
        SyslogTlsInput {
            host : Cow::Owned(host.into()),
            local_sender,
            local_receiver,
            log_sender,
            log_receiver,
            datasets : DatasetHolder::new(),
            #[cfg(feature="metrics")]
            metrics : generate_syslog_input_metrics(name),
            storage : Box::new(DummyStateStorage{})
        }
    }
    fn _increase_received_logs_metric(&self) {
        #[cfg(feature="metrics")]
        self.metrics.1.received_logs.inc();
    }
    fn increase_received_logs_metric_by(&self, total : usize) {
        #[cfg(feature="metrics")]
        self.metrics.1.received_logs.inc_by(total as i64);
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
    fn load_certs(&self, filename: &str) -> Result<Vec<CertificateDer<'static>>, SiemError> {
        let file = self.storage.get_file(filename)?;
        match rustls_pemfile::read_one_from_slice(&file) {
            Ok(Some(v)) => match v.0 {
                rustls_pemfile::Item::X509Certificate(cert) => Ok(vec![cert]),
                _ => Err(SiemError::Storage(usiem::err::StorageError::NotExists))
            },
            Err(err) => Err(SiemError::Configuration(format!("Invalid PEM certificate: {:?}", err))),
            Ok(None) => Err(SiemError::Configuration("Empty certificate".into()))
        }
    }
    
    /// Loads the server private key from a file
    fn load_private_key(&self, filename: &str) -> Result<PrivateKeyDer<'static>, SiemError> {
        let file = self.storage.get_file(filename)?;
        match rustls_pemfile::read_one_from_slice(&file) {
            Ok(Some(v)) => match v.0 {
                rustls_pemfile::Item::Pkcs1Key(key) => Ok(key.into()),
                rustls_pemfile::Item::Pkcs8Key(key) => Ok(key.into()),
                rustls_pemfile::Item::Sec1Key(key) => Ok(key.into()),
                _ => Err(SiemError::Configuration("Invalid key format".into()))
            },
            Err(err) => Err(SiemError::Configuration(format!("Invalid PEM certificate: {:?}", err))),
            Ok(None) => Err(SiemError::Configuration("Empty certificate".into()))
        }
    }

    fn get_certificate_filename(&self) -> Option<String> {
        let config : &TextMapSynDataset = self.datasets.get(&SiemDatasetType::Configuration)?.try_into().ok()?;
        let filename = config.get(CERTIFICATE_FILENAME_CONFIGURATION)?;
        Some(filename.to_string())
    }
    fn get_private_key_filename(&self) -> Option<String> {
        let config : &TextMapSynDataset = self.datasets.get(&SiemDatasetType::Configuration)?.try_into().ok()?;
        let filename = config.get(PRIVATE_KEY_FILENAME_CONFIGURATION)?;
        Some(filename.to_string())
    }
}


fn error(err: rustls::Error) -> SiemError {
    SiemError::Other(err.to_string())
}

#[cfg(test)]
mod tst {

    use super::*;
    use std::thread;
    use crate::testing::*;

    #[test]
    fn tls_syslog_basic_test() {
        let sys_input = SyslogTlsInput::new(TLS_LISTENING_HOST, SYSLOG_COMPONENT_NAME);
        let (capabilities, log_receiver) = prepare_syslog_basic_test(Box::new(sys_input));
        let mut client = testing_tls_client();
        let stream = client.stream();
        thread::sleep(std::time::Duration::from_millis(100));
        syslog_basic_test(stream, &capabilities, &log_receiver);
        drop(client);
        thread::sleep(std::time::Duration::from_millis(100));
        check_no_active_connections(&capabilities);
    }
}

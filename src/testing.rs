use std::io::Write;
use std::net::TcpStream;
use std::sync::Arc;
use std::thread;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::{ClientConfig, RootCertStore};
use usiem::components::SiemComponent;
use usiem::components::command::{SiemCommandHeader, SiemCommandCall};
use usiem::components::common::{NotificationLevel, SiemComponentCapabilities};
use usiem::components::dataset::holder::DatasetHolder;
use usiem::components::dataset::text_map::{TextMapDataset, TextMapSynDataset};
use usiem::components::dataset::SiemDataset;
use usiem::components::metrics::gauge::GaugeVec;
use usiem::components::metrics::{SiemMetric, SiemMetricDefinition};
use usiem::components::storage::{SiemComponentStateStorage, TestingStorage};
use usiem::components::{common::SiemMessage, metrics::counter::CounterVec};
use usiem::crossbeam_channel::{self, Receiver};
use usiem::events::SiemLog;

#[path = "./tls_client.rs"]
mod tls_client;

use crate::metrics::{
    active_connections_metric, received_bytes_metric, received_logs_metric,
    total_connections_metric,
};
use crate::tls::{CERTIFICATE_FILENAME_CONFIGURATION, PRIVATE_KEY_FILENAME_CONFIGURATION};

use self::tls_client::TlsClient;

pub const SYSLOG_COMPONENT_NAME: &'static str = "syslog123";
pub const TLS_LISTENING_HOST: &'static str = "127.0.0.1:21234";

pub const SERVER_CERTIFICATE: &'static [u8] = include_bytes!("../keys/usiem_syslog_test_21234.crt");
pub const CA_CERT: &'static [u8] = include_bytes!("../keys/usiem_syslog_ca.crt");
pub const SERVER_KEY: &'static [u8] = include_bytes!("../keys/usiem_syslog_test.key");

pub fn init_logging() {
    let log_receiver = usiem::logging::testing_component_logger_dummy();
    usiem::logging::enabled_level(&NotificationLevel::Debug);
    usiem::logging::set_max_level(NotificationLevel::Debug);
    std::thread::spawn(move || loop {
        let log = match log_receiver.recv() {
            Ok(v) => v,
            Err(_) => return,
        };
        match log {
            SiemMessage::Notification(log) => {
                println!(
                    "{} - {:?} - {} - {}",
                    log.timestamp, log.level, log.component_name, log.log
                )
            }
            _ => {}
        }
    });
}

pub fn testing_tls_client() -> TlsClient {
    let mut root_store = RootCertStore::empty();
    root_store.add_parsable_certificates(vec![get_ca_certificate()]);
    let config = ClientConfig::builder()
        .with_root_certificates(Arc::new(root_store))
        .with_no_client_auth();
    let config = Arc::new(config);
    let stream = TcpStream::connect(TLS_LISTENING_HOST).unwrap();
    let server_name = "localhost".to_string().try_into().unwrap();
    TlsClient::new(stream, server_name, config)
}

pub fn testing_datasets() -> DatasetHolder {
    let mut datasets = DatasetHolder::new();
    let mut configuration = TextMapDataset::new();
    configuration.insert(CERTIFICATE_FILENAME_CONFIGURATION, "/tls_comp/cert.pem");
    configuration.insert(PRIVATE_KEY_FILENAME_CONFIGURATION, "/tls_comp/key.key");
    let (comm, _) = usiem::crossbeam_channel::unbounded();
    let configuration = TextMapSynDataset::new(Arc::new(configuration), comm);
    datasets.insert(SiemDataset::Configuration(configuration));
    datasets
}

pub fn testing_storage() -> Box<dyn SiemComponentStateStorage> {
    let mut storage = TestingStorage::new();
    storage
        .set_file("/tls_comp/cert.pem", SERVER_CERTIFICATE.to_vec())
        .unwrap();
    storage
        .set_file("/tls_comp/key.key", SERVER_KEY.to_vec())
        .unwrap();
    Box::new(storage)
}

pub fn metrics_shold_match(
    metrics: &[SiemMetricDefinition],
    received_logs: usize,
    bytes_received: usize,
    connections: usize,
    active_connections: usize,
) {
    assert_eq!(
        received_logs as i64,
        get_received_logs_metric(metrics)
            .with_labels(&[])
            .unwrap()
            .get()
    );
    assert_eq!(
        bytes_received as i64,
        get_received_bytes_metric(metrics)
            .with_labels(&[])
            .unwrap()
            .get()
    );
    assert_eq!(
        active_connections as f64,
        get_active_connections_metric(metrics)
            .with_labels(&[])
            .unwrap()
            .get()
    );
    assert_eq!(
        connections as i64,
        get_total_connections_metric(metrics)
            .with_labels(&[])
            .unwrap()
            .get()
    );
}

pub fn get_received_logs_metric(metrics: &[SiemMetricDefinition]) -> &CounterVec {
    get_counter_metric(
        received_logs_metric(SYSLOG_COMPONENT_NAME).as_str(),
        metrics,
    )
}
pub fn get_received_bytes_metric(metrics: &[SiemMetricDefinition]) -> &CounterVec {
    get_counter_metric(
        received_bytes_metric(SYSLOG_COMPONENT_NAME).as_str(),
        metrics,
    )
}
pub fn get_total_connections_metric(metrics: &[SiemMetricDefinition]) -> &CounterVec {
    get_counter_metric(
        total_connections_metric(SYSLOG_COMPONENT_NAME).as_str(),
        metrics,
    )
}
pub fn get_active_connections_metric(metrics: &[SiemMetricDefinition]) -> &GaugeVec {
    get_gauge_metric(
        active_connections_metric(SYSLOG_COMPONENT_NAME).as_str(),
        metrics,
    )
}

pub fn get_counter_metric<'a>(name: &str, metrics: &'a [SiemMetricDefinition]) -> &'a CounterVec {
    for metric in metrics {
        if metric.name() == name {
            if let SiemMetric::Counter(counter) = metric.metric() {
                return counter;
            } else {
                panic!("Bad metric format")
            }
        }
    }
    panic!("Metric {} not found", name)
}
pub fn get_gauge_metric<'a>(name: &str, metrics: &'a [SiemMetricDefinition]) -> &'a GaugeVec {
    for metric in metrics {
        if metric.name() == name {
            if let SiemMetric::Gauge(counter) = metric.metric() {
                return counter;
            } else {
                panic!("Bad metric {} format", name)
            }
        }
    }
    panic!("Metric {} not found", name)
}
#[allow(dead_code)]
pub fn get_server_certificate() -> CertificateDer<'static> {
    match rustls_pemfile::read_one_from_slice(SERVER_CERTIFICATE)
        .unwrap()
        .unwrap()
        .0
    {
        rustls_pemfile::Item::X509Certificate(cert) => cert,
        _ => panic!("Cannot extract certificate for testing"),
    }
}
#[allow(dead_code)]
pub fn get_server_key() -> PrivateKeyDer<'static> {
    match rustls_pemfile::read_one_from_slice(SERVER_KEY)
        .unwrap()
        .unwrap()
        .0
    {
        rustls_pemfile::Item::Pkcs1Key(key) => key.into(),
        rustls_pemfile::Item::Pkcs8Key(key) => key.into(),
        rustls_pemfile::Item::Sec1Key(key) => key.into(),
        _ => panic!("Cannot get server key for testing"),
    }
}

pub fn get_ca_certificate() -> CertificateDer<'static> {
    match rustls_pemfile::read_one_from_slice(CA_CERT) {
        Ok(Some((rustls_pemfile::Item::X509Certificate(cert), _))) => cert,
        _ => panic!("Cannot extract CA certificate for testing"),
    }
}

pub fn prepare_syslog_basic_test(mut sys_input : Box<dyn SiemComponent>) -> (SiemComponentCapabilities, Receiver<SiemLog>) {
    let (log_sender, log_receiver) = crossbeam_channel::bounded(1000);
        sys_input.set_log_channel(log_sender, log_receiver.clone());
        sys_input.set_datasets(testing_datasets());
        sys_input.set_storage(testing_storage());
        let local_sender = sys_input.local_channel();
        let capabilities = sys_input.capabilities();
        thread::spawn(move || {
            init_logging();
            let _ = sys_input.run().unwrap();
        });

        thread::spawn(move || {
            thread::sleep(std::time::Duration::from_millis(2000));
            let _sended = local_sender.send(SiemMessage::Command(
                SiemCommandHeader {
                    comm_id: 0,
                    comp_id: 0,
                    user: "KERNEL".to_string(),
                },
                SiemCommandCall::STOP_COMPONENT("ComponentToStop".to_string()),
            ));
        });
        (capabilities, log_receiver)
}

pub fn syslog_basic_test<S>(mut stream : S, capabilities : &SiemComponentCapabilities, log_receiver : &Receiver<SiemLog>) where S: Write {
    thread::sleep(std::time::Duration::from_millis(10));
    
    let first = b"This is the first log\nThis is the second log\nThis is the third log";
    let second = b" with extra\n";
    let total_sent = first.len() + second.len();
    stream
        .write_all(first)
        .expect("Must send logs");
    thread::sleep(std::time::Duration::from_millis(1000));// TODO: When standarized TCP KeepAlive for sockets add more than 1 second (Default in windows)
    stream
        .write_all(second)
        .expect("Must send logs");
    println!("Writed all logs");
    stream.flush().unwrap();
    println!("Flushed logs");
    thread::sleep(std::time::Duration::from_millis(200));
    let log = log_receiver.recv().expect("Must receive first log");
    assert_eq!("This is the first log", log.message());
    let log = log_receiver.recv().expect("Must receive second log");
    assert_eq!("This is the second log", log.message());
    let log = log_receiver.recv().expect("Must receive third log");
    assert_eq!("This is the third log with extra", log.message());
    metrics_shold_match(capabilities.metrics(), 3, total_sent, 1, 1);
}

pub fn check_no_active_connections(capabilites : &SiemComponentCapabilities) {
    assert_eq!(
        0.0,
        get_active_connections_metric(capabilites.metrics())
            .with_labels(&[])
            .unwrap()
            .get()
    );
}
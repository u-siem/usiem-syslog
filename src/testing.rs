use std::sync::Arc;

use usiem::components::dataset::SiemDataset;
use usiem::components::dataset::holder::DatasetHolder;
use usiem::components::dataset::text_map::{TextMapSynDataset, TextMapDataset};
use usiem::components::storage::{SiemComponentStateStorage, TestingStorage};
use usiem::components::{metrics::counter::CounterVec, common::SiemMessage};
use usiem::components::metrics::gauge::GaugeVec;
use usiem::components::metrics::{SiemMetric, SiemMetricDefinition};

use crate::metrics::{
    active_connections_metric, received_bytes_metric, received_logs_metric,
    total_connections_metric,
};
use crate::tls::{CERTIFICATE_FILENAME_CONFIGURATION, PRIVATE_KEY_FILENAME_CONFIGURATION};

pub const SYSLOG_COMPONENT_NAME: &'static str = "syslog123";
pub const TCP_LISTENING_HOST : &'static str = "127.0.0.1:13333";
pub const TLS_LISTENING_HOST : &'static str = "127.0.0.1:13334";

pub fn init_logging() {
    let log_receiver = usiem::logging::testing_component_logger_dummy();
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
    storage.set_file("/tls_comp/cert.pem", vec![]).unwrap();
    storage.set_file("/tls_comp/key.key", vec![]).unwrap();
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

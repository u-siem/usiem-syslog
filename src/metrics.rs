use std::borrow::Cow;

use usiem::prelude::{
    counter::{Counter, CounterVec},
    gauge::{Gauge, GaugeVec},
    metrics::*,
};

pub fn received_logs_metric(name : &str) -> String {
    format!("syslog_{}_received_logs", name.to_lowercase())
}
pub fn active_connections_metric(name : &str) -> String {
    format!("syslog_{}_active_connections", name.to_lowercase())
}
pub fn total_connections_metric(name : &str) -> String {
    format!("syslog_{}_total_connections", name.to_lowercase())
}
pub fn received_bytes_metric(name : &str) -> String {
    format!("syslog_{}_received_bytes", name.to_lowercase())
}

pub fn generate_syslog_input_metrics(name : &str) -> (Vec<SiemMetricDefinition>, SyslogMetrics) {
    let received_logs = SiemMetricDefinition::new(
        Cow::Owned(received_logs_metric(name)),
        Cow::Borrowed("Number of logs in the parsing queue"),
        SiemMetric::Counter(CounterVec::new(&[&[]])),
    )
    .unwrap();
    let active_connections = SiemMetricDefinition::new(
        Cow::Owned(active_connections_metric(name)),
        Cow::Borrowed("Number of active connections for this syslog instance"),
        SiemMetric::Gauge(GaugeVec::new(&[&[]])),
    )
    .unwrap();
    let total_connections = SiemMetricDefinition::new(
        Cow::Owned(total_connections_metric(name)),
        Cow::Borrowed("Number of connections performed for this syslog instance"),
        SiemMetric::Counter(CounterVec::new(&[&[]])),
    )
    .unwrap();
    let received_bytes = SiemMetricDefinition::new(
        Cow::Owned(received_bytes_metric(name)),
        Cow::Borrowed("Total of bytes received by this syslog instance"),
        SiemMetric::Counter(CounterVec::new(&[&[]])),
    )
    .unwrap();
    let metrics = SyslogMetrics {
        received_logs: get_metric_counter(&received_logs),
        active_connections: get_metric(&active_connections),
        total_connections: get_metric_counter(&total_connections),
        received_bytes : get_metric_counter(&received_bytes),
    };
    (vec![received_logs, active_connections, total_connections, received_bytes], metrics)
}

fn get_metric(definition: &SiemMetricDefinition) -> Gauge {
    let gauge_vec: GaugeVec = definition.metric().try_into().unwrap();
    gauge_vec.with_labels(&[]).unwrap().clone()
}
fn get_metric_counter(definition: &SiemMetricDefinition) -> Counter {
    let vc: CounterVec = definition.metric().try_into().unwrap();
    vc.with_labels(&[]).unwrap().clone()
}

#[derive(Clone)]
pub struct SyslogMetrics {
    pub received_logs: Counter,
    pub active_connections: Gauge,
    pub total_connections: Counter,
    pub received_bytes : Counter
}
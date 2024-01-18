# uSIEM Syslog

[![crates.io](https://img.shields.io/crates/v/usiem-syslog.svg?style=for-the-badge&logo=rust)](https://crates.io/crates/usiem-syslog) [![documentation](https://img.shields.io/badge/read%20the-docs-9cf.svg?style=for-the-badge&logo=docs.rs)](https://docs.rs/usiem-syslog) [![MIT License](https://img.shields.io/crates/l/usiem-syslog?style=for-the-badge)](https://github.com/u-siem/usiem-syslog/blob/main/LICENSE) [![Rust](https://img.shields.io/github/actions/workflow/status/u-siem/usiem-syslog/rust.yml?style=for-the-badge)](https://github.com/u-siem/usiem-syslog/workflows/Rust/badge.svg?branch=main)

uSIEM Syslog input and output. Receive and send logs using syslog.

## Metrics
By default the feature "metrics" is enabled generating 4 different metrics:

* syslog_XXX_received_logs: Total received logs by the XXX listener
* syslog_XXX_active_connections: Active connections to the XXX listener
* syslog_XXX_total_connections: Total number of connections accepted by the XXX listener
* syslog_XXX_received_bytes: Total number of received bytes by the XXX listener
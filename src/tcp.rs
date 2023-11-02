use coarsetime::Instant;
use usiem::chrono::Datelike;
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

#[derive(Clone)]
pub struct SyslogInput {
    host: Cow<'static, str>,
    local_sender: Sender<SiemMessage>,
    local_receiver: Receiver<SiemMessage>,
    log_sender: Sender<SiemLog>,
    log_receiver: Receiver<SiemLog>
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
            vec![],
        );
    }

    fn run(&mut self) -> Result<(), SiemError> {
        let listener = match TcpListener::bind(&self.host[..]) {
            Ok(v) => v,
            Err(_) => {
                return Err(SiemError::Io(format!("Cannot start TCP syslog listener on port: {}", self.host)));
            }
        };
        let _ = listener.set_nonblocking(true);

        let local_receiver = self.local_receiver.clone();
        let log_sender = self.log_sender.clone();
        let _updater_counter = 0;
        let mut listeners = LinkedList::new();
        let mut buffer = [0; 4096];
        loop {
            Instant::update();
            match listener.accept(){
                Ok(v) => {
                    listeners.push_back((v.0, Vec::with_capacity(1024)));
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
                            info!("Error in connection, {:?}", e);
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
                            _ => {
                                continue
                            },
                        }
                    }
                };
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
                        error!("{}", usiem::serde_json::to_string(&err.0).unwrap_or_default());
                        break;
                    }
                }
                listeners.push_front((stream, text_log));

            };
        }
    }

    fn duplicate(&self) -> Box<dyn SiemComponent> {
        Box::new(self.clone())
    }

    fn set_datasets(&mut self, _datasets: DatasetHolder) {
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
        SyslogInput {
            host,
            local_sender,
            local_receiver,
            log_sender,
            log_receiver
        }
    }
}

pub fn parse_log(txt : &[u8]) -> SiemLog {
    let content = String::from_utf8_lossy(txt);
    let (created, origin) = match parse_header(&content) {
        Some(v) => v,
        None => (Instant::recent().as_u64() as i64, "Syslog")
    };
    let origin: String = origin.to_string();
    let mut log = SiemLog::new(content, Instant::recent().as_u64() as i64, origin);
    log.set_event_created(created);
    log
}

fn parse_header(txt : &str) -> Option<(i64, &str)> {
    let pri_end = match txt[0..5].find(">") {
        Some(pos) => pos + 1,
        None => 0
    };
    let header= &txt[pri_end..];
    let mut split = header.split(|v| v == ' ');
    let month_or_version = split.next()?;
    match month_or_version.parse::<u32>() {
        Ok(_) => {
            let datetime = split.next()?;
            let hostname = split.next()?;
            let date = usiem::chrono::NaiveDateTime::parse_from_str(datetime, "%Y-%m-%dT%H:%M:%S%.fZ").ok()?.and_utc();
            Some((date.timestamp_millis(), hostname))
        }, // version
        Err(_) => {
            let day = split.next()?;
            let day = if day == "" {
                split.next()?
            }else {
                day
            };
            let time = split.next()?;
            let hostname = split.next()?;
            let year = usiem::chrono::Utc::now().year();
            let txt = format!("{} {} {} {}", day, month_or_version, year, time);
            let date = usiem::chrono::NaiveDateTime::parse_from_str(&txt, "%d %b %Y %H:%M:%S").ok()?.and_utc();
            Some((date.timestamp_millis(), hostname))
        },
    }
}

#[cfg(test)]
mod tst {
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

        let mut stream =
            std::net::TcpStream::connect("localhost:13333").expect("Must connect to localhost");
        let _writed = stream
            .write(b"This is the first log\nThis is the second log\nThis is the third log")
            .expect("Must send logs");
        match stream.flush() {
            Ok(_) => {}
            Err(e) => {
                println!("{}", e);
            }
        };
        let _writed = stream
            .write(b" with extra\n")
            .expect("Must send logs");
        match stream.flush() {
            Ok(_) => {}
            Err(e) => {
                println!("{}", e);
            }
        };
        thread::sleep(std::time::Duration::from_millis(50));
        let log = log_receiver.recv().expect("Must receive first log");
        assert_eq!(log.message(), "This is the first log");
        let log = log_receiver.recv().expect("Must receive second log");
        assert_eq!(log.message(), "This is the second log");
        
        let log = log_receiver.recv().expect("Must receive second log");
        assert_eq!(log.message(), "This is the third log with extra");
    }


    #[test]
    fn parses_syslog_msg() {
        let log = b"<134>Aug 23 20:30:25 OPNsense.localdomain filterlog[21853]: 82,,,0,igb0,match,pass,out,4,0x0,,62,25678,0,DF,17,udp,60,192.168.1.8,8.8.8.8,5074,53,40";
        let log = parse_log(log);
        let year = usiem::chrono::Utc::now().year();
        let date = usiem::chrono::NaiveDateTime::parse_from_str(&format!("{}-8-23T20:30:25.0Z",year), "%Y-%m-%dT%H:%M:%S%.fZ").ok().unwrap().and_utc();
        assert_eq!(date.timestamp_millis(), log.event_created());
        assert_eq!("OPNsense.localdomain", log.origin());

        let log = b"<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - BOM'su root' failed for lonvick on /dev/pts/8";
        let log = parse_log(log);
        assert_eq!(1065910455003, log.event_created());
        assert_eq!("mymachine.example.com", log.origin());

        let log = b"<34>Oct 11 00:14:05 mymachine su: 'su root' failed for lonvick on /dev/pts/8";
        let log = parse_log(log);
        let year = usiem::chrono::Utc::now().year();
        let date = usiem::chrono::NaiveDateTime::parse_from_str(&format!("{}-10-11T00:14:05.0Z",year), "%Y-%m-%dT%H:%M:%S%.fZ").ok().unwrap().and_utc();
        assert_eq!(date.timestamp_millis(), log.event_created());
        assert_eq!("mymachine", log.origin());

        let log = b"<13>Feb  5 17:32:18 10.0.0.99 myTag Use the BFG!";
        let log = parse_log(log);
        let year = usiem::chrono::Utc::now().year();
        let date = usiem::chrono::NaiveDateTime::parse_from_str(&format!("{}-2-5T17:32:18.0Z",year), "%Y-%m-%dT%H:%M:%S%.fZ").ok().unwrap().and_utc();
        assert_eq!(date.timestamp_millis(), log.event_created());
        assert_eq!("10.0.0.99", log.origin());
    }
}

use coarsetime::Instant;
use usiem::{events::SiemLog, chrono::Datelike, crossbeam_channel::Sender};


pub fn read_log(buffer : &[u8], text_log : &mut Vec<u8>,sender : &Sender<SiemLog>) -> usize {
    let mut splited_buf = buffer.split_inclusive(|&v| v == b'\n');
    let mut sent = 0;
    while let Some(v) = splited_buf.next() {
        let partial_buffer = if !v.is_empty() && v[v.len() - 1] == b'\n' {
            & v[0..v.len() - 1]
        }else {
            text_log.extend_from_slice(v);
            break;
        };
        let log = if text_log.is_empty() {
            SiemLog::new(String::from_utf8_lossy(&partial_buffer), Instant::recent().as_u64() as i64, "Syslog")
        }else {
            text_log.extend(partial_buffer.iter());
            let log = SiemLog::new(String::from_utf8_lossy(&text_log[0..text_log.len()]), Instant::recent().as_u64() as i64, "Syslog");
            text_log.truncate(0);
            log
        };
        if let Err(err) = sender.send(log) {
            usiem::warn!("Error sending log: {}", usiem::serde_json::to_string(&err.0).unwrap_or_default());
            break
        }
        sent += 1;
    }
    sent
}
#[allow(dead_code)]
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
#[allow(dead_code)]
fn parse_header(txt : &str) -> Option<(i64, &str)> {
    let pri_end = match txt[0..5].find('>') {
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
            let day = if day.is_empty() {
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

#[test]
#[ignore]
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
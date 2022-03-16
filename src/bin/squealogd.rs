use chrono::prelude::*;
use std::io::Read;
use syslog_loose::{Message, ProcId, Protocol};
use systemstat::Platform;

#[cfg(target_os = "freebsd")]
fn parse_klog_line<'a>(input: &'a str, boottime: &DateTime<Utc>) -> Message<&'a str> {
    use nom::{
        bytes::complete::tag,
        character::complete::digit1,
        combinator::{map, map_res, opt, rest},
        sequence::{delimited, tuple},
        IResult,
    };
    use std::str::FromStr;

    fn digits<T>(input: &str) -> IResult<&str, T>
    where
        T: FromStr,
    {
        map_res(digit1, FromStr::from_str)(input)
    }

    tuple((
        map(
            opt(delimited(
                tag("<"),
                map(digits, syslog_loose::decompose_pri),
                tag(">"),
            )),
            |pri| pri.unwrap_or((None, None)),
        ),
        opt(delimited(tag("["), digits, tag("]"))),
        rest,
    ))(input)
    .map(|(_, ((facility, severity), ts, rest))| Message {
        protocol: Protocol::RFC5424(69),
        facility,
        severity,
        timestamp: ts.map(|n| (*boottime + chrono::Duration::seconds(n)).into()),
        hostname: None,
        appname: None,
        procid: None,
        msgid: None,
        structured_data: vec![],
        msg: rest.trim(),
    })
    .unwrap_or(Message {
        facility: None,
        severity: None,
        timestamp: None,
        hostname: None,
        appname: None,
        procid: None,
        msgid: None,
        protocol: Protocol::RFC3164,
        structured_data: vec![],
        msg: input,
    })
}

#[derive(Debug)]
enum LogTransport {
    Udp(std::net::UdpSocket),
    UnixDgram(std::os::unix::net::UnixDatagram),
    #[cfg(target_os = "freebsd")]
    Klog(std::fs::File),
}

#[derive(Debug)]
struct LogSource {
    xport: LogTransport,
    event: polling::Event,
    sockname: String,
}

fn main() -> anyhow::Result<()> {
    let systemstat = systemstat::System::new();
    #[cfg(target_os = "freebsd")]
    let boottime = systemstat.boot_time()?;

    let mut conn = rusqlite::Connection::open(
        std::env::var("SQUEALOG_DB").unwrap_or_else(|_| "/var/log/log.db".to_string()),
    )?;

    conn.pragma_update(None, "journal_mode", &"WAL")?;
    conn.pragma_update(None, "wal_autocheckpoint", &"128")?;

    rusqlite_migration::Migrations::new(vec![rusqlite_migration::M::up(include_str!(
        "../sql/1.sql"
    ))])
    .to_latest(&mut conn)?;

    let ingest = |socket: &str, msg: Message<&str>| {
        // eprintln!("{}! {:#?}", socket, msg);
        conn.prepare_cached(
            "INSERT INTO log (facility, severity, socket, appname, pid, time, msg)
             VALUES (:facility, :severity, :socket, :appname, :pid, :time, :msg)",
        )?
        .execute(rusqlite::named_params! {
            ":facility": msg.facility.map(|x| x as i64),
            ":severity": msg.severity.map(|x| x as i64),
            ":socket": socket,
            ":appname": msg.appname,
            ":pid": msg.procid.and_then(|p| match p {
                 ProcId::PID(i) => Some(i),
                 _ => None,
             }),
            ":time": msg.timestamp,
            ":msg": msg.msg
        })
    };

    let mut socks = listenfd::ListenFd::from_env();
    let mut sources = vec![];
    for (i, n) in std::env::var("LISTEN_FDNAMES")?.split(':').enumerate() {
        let xport = socks
            .take_unix_datagram(i)
            .map(|x| x.map(LogTransport::UnixDgram))
            .or_else(|_| socks.take_udp_socket(i).map(|x| x.map(LogTransport::Udp)))?
            .ok_or(anyhow::format_err!("Socket used twice"))?;
        match xport {
            LogTransport::Udp(ref s) => s.set_nonblocking(true),
            LogTransport::UnixDgram(ref s) => s.set_nonblocking(true),
            #[cfg(target_os = "freebsd")]
            LogTransport::Klog(_) => unreachable!(),
        }?;
        sources.push(LogSource {
            xport,
            event: polling::Event::readable(i),
            sockname: n.to_owned(),
        });
    }

    #[cfg(target_os = "freebsd")]
    {
        use std::os::unix::fs::OpenOptionsExt;
        sources.push(LogSource {
            xport: LogTransport::Klog(
                std::fs::OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NONBLOCK)
                    .open("/dev/klog")
                    .unwrap(),
            ),
            event: polling::Event::readable(usize::MAX - 1),
            sockname: "klog".to_owned(),
        })
    };

    let poller = polling::Poller::new()?;
    for source in &sources {
        match source.xport {
            LogTransport::Udp(ref s) => poller.add(s, source.event),
            LogTransport::UnixDgram(ref s) => poller.add(s, source.event),
            #[cfg(target_os = "freebsd")]
            LogTransport::Klog(ref f) => poller.add(f, source.event),
        }?
    }

    let mut buf = vec![0u8; 8192];
    let mut events = Vec::new();
    loop {
        events.clear();
        poller.wait(&mut events, None)?;

        for ev in &events {
            let source = sources
                .iter_mut()
                .find(|source| source.event.key == ev.key)
                .unwrap();
            match source.xport {
                LogTransport::Udp(ref s) => {
                    let len = s.recv(&mut buf).unwrap();
                    let line = std::str::from_utf8(&buf[0..len])?;
                    ingest(&source.sockname, syslog_loose::parse_message(&line))?;
                    poller.modify(s, source.event)?;
                }
                LogTransport::UnixDgram(ref s) => {
                    let len = s.recv(&mut buf).unwrap();
                    let line = std::str::from_utf8(&buf[0..len])?;
                    ingest(&source.sockname, syslog_loose::parse_message(&line))?;
                    poller.modify(s, source.event)?;
                }
                #[cfg(target_os = "freebsd")]
                LogTransport::Klog(ref mut f) => {
                    loop {
                        match f.read(&mut buf) {
                            Ok(len) => {
                                let msgs = std::str::from_utf8(&buf[0..len])?;
                                for line in msgs.lines() {
                                    ingest(&source.sockname, parse_klog_line(line, &boottime))?;
                                }
                            }
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                            Err(e) => panic!("{:?}", e),
                        }
                    }
                    poller.modify(&*f, source.event)?;
                }
            }
        }
    }
}

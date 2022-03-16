# Squealog: DankBSD's logging system

Goals:

- avoid configuration at all costs, since we aim for as much statelessness as possible
- store structured data (provided via RFC 5424, as well as the metadata) in a structured way
- do not reinvent wheels, reuse all the code
- provide pretty viewer interfaces (TODO)

Non-goals: (anything that goes beyond simple desktop usage)

- scalability
- forwarding
- durability/backups

Maybe-goals:

- support journald's extended protocol?

Why the name?
Well, people like to say that SQL is properly pronounced as "sequel" (since SEQUEL was the original name).
I like to joke that "squeal" would be the better way to pronounce it.
Hence "SQL log" → squealog.

## `squealogd`

A daemon that writes incoming syslog and FreeBSD kernel log messages to a SQLite database.

- basically no configuration
	- uses socket activation (systemd protocol, names are mandatory) for sockets
	- the `SQUEALOG_DB` env var overrides the database path (`/var/log/log.db` by default)
- portable to other systems (uses the [polling](https://github.com/smol-rs/polling) crate, only builds klog stuff on `freebsd`)
- can parse crappy messages thanks to [syslog-loose](https://github.com/StephenWakely/syslog-loose)
- automatically deletes old messages using a SQLite trigger

Testing with [systemfd](https://github.com/mitsuhiko/systemfd):

```bash
doas rm /var/run/log*; doas env LISTEN_FDNAMES=udp:log:logpriv $(which systemfd) -s udp::514 -s unixdgram::/var/run/log -s unixdgram::/var/run/logpriv -- $PWD/target/release/squealogd
```

## License

This is free and unencumbered software released into the public domain.  
For more information, please refer to the `UNLICENSE` file or [unlicense.org](https://unlicense.org).

## Resurrection and enhancements of [Dug Song's](https://en.wikipedia.org/wiki/W00w00) all-time-classic network sniffer:

* Hides the command line options (`ENV_ARGS=`) from the process list (`ps`).
* Show Banners (`-v`).
* HTTP parsing improvements & Cookie logging.
* No duplicates: Reports each result only once.
* Stand-alone & static binary (no need for dsniff.magic/dsniff.services)
* Deep-Packet-Inspection (`-m`). Port agnostic.


Download the [Pre Compiled Static Binary](https://github.com/hackerschoice/dsniff/releases/latest) for Linux, FreeBSD and OpenBSD.

```sh
curl -SsfL "https://github.com/hackerschoice/dsniff/releases/latest/download/dsniff_linux-$(uname -m)" -o dsniff
```

Run (example):
```sh
export ENV_ARGS="-i eth0 -v -m not port 443" # hide options from the process list
./dsniff
```

The reason why I prefer dsniff over most others:
1. The results give a quick overview who/where SSL/SSH is being used.
1. It logs Cookies and Session IDs.
1. It shows plaintext HTTP `Location: ` redirects to HTTPS.
1. It shows WireGuard or SSH on non-default ports (like port 31337). Those tend to be worthy admins.

![dsniff-thc-screenshot](https://github.com/hackerschoice/dsniff/assets/5938498/d3eeb16c-dd64-41f6-b839-ca7a70e34778)

Compile:
```sh
./configure --enable static && make dsniff
```

### Useful parameters:  
`-C` - Force Color [default is to show color on TTY only]  
`-P` - Use promisc mode  
`-v` - Show banners (SNI, SSH, HTTP, Cookies, ...)  
`-m` - Detect protocol regardless of the port (e.g ssh on port 222 etc).  

Compare [original](https://packages.debian.org/source/unstable/dsniff): [Diff](https://github.com/hackerschoice/dsniff/compare/orig...main)  
Original [README](README)

---
Similar tools:
* https://github.com/lgandx/PCredz
* https://github.com/DanMcInerney/net-creds


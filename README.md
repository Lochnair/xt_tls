# xt_tls

xt\_tls is an extension for netfilter/IPtables that allows you to filter traffic based on TLS hostnames.

## Features
- Filter TLS traffic based on the SNI extension

## Todo
- Add more advanced matching features (i.e. wildcard matching)
- Add support for matching on the server certificate

## Manual Installation

### Prerequisites
- Kernel headers (`apt install linux-headers-$(uname -r)` or `yum install kernel-devel`)
- IPtables devel (`apt install iptables-dev` or `yum install iptables-devel`)
- Glob kernel module
- Netfilter defrag modules: nf\_defrag\_ipv4 and nf\_defrag\_ipv6

```bash
git clone https://github.com/Lochnair/xt_tls.git
cd xt_tls
make
sudo make install
```

## [DKMS](https://en.wikipedia.org/wiki/Dynamic_Kernel_Module_Support) Installation

### Additional Prerequisites
- DKMS (`apt install dkms` or `yum install dkms` (from EPEL) )

```bash
git clone https://github.com/Lochnair/xt_tls.git
cd xt_tls
sudo make dkms-install
```

## Usage

You can block traffic to Facebook using the following command.

```bash
sudo iptables -A OUTPUT -p tcp --dport 443 -m tls --tls-host "www.facebook.com" -j DROP
```

You can also match subdomains using wildcards like this.

```bash
sudo iptables -A OUTPUT -p tcp --dport 443 -m tls --tls-host "\*.googlevideo.com" -j DROP
```

## Bugs
If you encounter a bug please make sure to include the following things in your bug report:
- The application used for sending the request
- The domain your trying to allow/block - Debug output (see the debugging section below)
- If possible, a TCPDump capture containing the TLS "Client/Server Hello's"

## Debugging

Since xt\_tls is not thoroughly tested, sometimes weird things happen. This might be caused by an application that sends packets xt\_tls can't parse. For example cURL and wget (or the TLS libary they use) doesn't send a session ID in the "Client Hello", and xt\_tls didn't understand that, so I had to change some things to make it work.

By default xt\_tls doesn't print anything to the syslog, as there seems to be quite some overhead in doing that. However you can enable debug output by compiling xt\_tls like below.

```bash
make debug
```

If you've sent a TLS request, you can now use dmesg to see if everything works as expected.
```bash
dmesg

[ 2013.959415] [xt_tls] Session ID length: 32
[ 2013.974006] [xt_tls] Cipher len: 42
[ 2013.974292] [xt_tls] Offset (1): 119
[ 2013.974583] [xt_tls] Compression length: 1
[ 2013.974915] [xt_tls] Offset (2): 122
[ 2013.975211] [xt_tls] Extensions length: 38
[ 2013.977016] [xt_tls] Name type: 0
[ 2013.977675] [xt_tls] Name length: 10
[ 2013.978664] [xt_tls] Parsed domain: github.com
[ 2013.979068] [xt_tls] Domain matches: false, invert: false
```

## Credits

I would like to thank the people behind the nDPI project, as the parsing function is inspired by their work.

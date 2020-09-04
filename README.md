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
sudo iptables -A OUTPUT -p tcp --dport 443 -m tls --tls-host "*.googlevideo.com" -j DROP
```
Another way to specify the hostname matching patterns is to use the hostsets. This is a way to do when you have to match each packet  with a lot of potentially suitable hostnames. While you may write a separate iptables rule for each hostname, it would be very inefficient. A better way is place all the hostnames to the single collection named "hostset". The hostsets are similar to the [ipsets](http://ipset.netfilter.org/) with the difference that they contain host names rather than ip-addresses. The entire hostset can be matches with a single iptables rule:

```bash
sudo iptables -A OUTPUT -p tcp --dport 443 -m tls --tls-hostset blacklist -j DROP
```
This is far more efficient than write a chain consisting of many similar rules. Technically a hostset is a binary tree, which stores hostnames in the lexicographically reversed form (for faster suffix matching). Hostsets are created automatically, as soon as the first iptables rule referencing this hostset is created. They are also destroyed automatically after the deletion of the last rule that uses this hostset.

The hostsets are created empty, so they match nothing at this moment. You should populate a newly created hostset. All manipulations with a hostset content are done using the /proc filesystems:
```bash
sudo echo +facebook.com > /proc/net/xt_tls/hostset/blacklist
sudo echo +googlevideo.com > /proc/net/xt_tls/hostset/blacklist
...
```
Each hostset has a corresponding file in the "/proc/net/xt_tls/hostset" directory, which may be used to manipulate its content. The protocol is similar to that of the "xt_recent" iptables extension.

To add a new hostname to the hostset, you should write this name, perfixed with a '+' sign to the corresponding /proc file, as above.

To remove an individual hostname from the set you should put this name prefixed with a '-' sign to the /proc file:
```bash
sudo echo -facebook.com > /proc/net/xt_tls/hostset/blacklist
```
To flush the entire hostset content (to remove all the names), write a '/' character to the proc file:
```bash
sudo echo / > /proc/net/xt_tls/hostset/blacklist
```
To get the current content of the hostset (together with hostname hit statistics), just read the corresponding /proc file:
```bash
cat /proc/net/xt_tls/hostset/blacklist

  298776098 facebook.com
 8736567589 googlevideo.com
          0 some.forgotten.site
 ...
```

You can not use wildcards with the hostsets. But you can use suffix matching instead. By default the host name set should match some hostset element exactly the entire rule also to match. But with "--tls-suffix" option it is enough when any host name suffix to match any hostset element. For example the following rule

```bash
sudo iptables -A OUTPUT -p tcp --dport 443 -m tls --tls-hostset blacklist --tls-suffix -j DROP
```
with the same hostset:

```bash
sudo echo +facebook.com > /proc/net/xt_tls/hostset/blacklist
sudo echo +googlevideo.com > /proc/net/xt_tls/hostset/blacklist
...
```
will match "facebook.com", "facebook.com", "anything.facebook.com" etc.

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

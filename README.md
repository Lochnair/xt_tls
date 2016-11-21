#xt_ssl

xt\_ssl is an extension for netfilter/IPtables that allows you to filter traffic based on SSL hostnames.

##Features
- Filter SSL traffic based on the SNI extension

##Todo
- Add more advanced matching features (i.e. wildcard matching)
- Add support for matching on the server certificate

##Installation

```bash
git clone https://github.com/Lochnair/xt_ssl.git
cd xt_ssl
make
sudo make install
```

##Usage

You can block traffic to Facebook using the following command.

```bash
sudo iptables -A OUTPUT -p tcp --dport 443 -m ssl --ssl-host "www.facebook.com" -j DROP
```

##Bugs
If you encounter a bug please make sure to include the following things in your bug report:
- The application used for sending the request
- The domain your trying to allow/block
- Debug output (see the debugging section below)
- If possible, a TCPDump capture containing the SSL "Client/Server Hello's"

##Debugging

Since xt\_ssl is not thoroughly tested, sometimes weird things happen. This might be caused by an application that sends packets xt\_ssl can't parse. For example cURL and wget (or the SSL libary they use) doesn't send a session ID in the "Client Hello", and xt\_ssl didn't understand that, so I had to change some things to make it work.

By default xt\_ssl doesn't print anything to the syslog, as there seems to be quite some overhead in doing that. However you can enable debug output by compiling xt\_ssl like below.

```bash
make debug
```

If you've sent a SSL request, you can now use dmesg to see if everything works as expected.
```bash
dmesg

[ 2013.959415] [xt_ssl] Session ID length: 32
[ 2013.974006] [xt_ssl] Cipher len: 42
[ 2013.974292] [xt_ssl] Offset (1): 119
[ 2013.974583] [xt_ssl] Compression length: 1
[ 2013.974915] [xt_ssl] Offset (2): 122
[ 2013.975211] [xt_ssl] Extensions length: 38
[ 2013.977016] [xt_ssl] Name type: 0
[ 2013.977675] [xt_ssl] Name length: 10
[ 2013.978664] [xt_ssl] Parsed domain: github.com
[ 2013.979068] [xt_ssl] Domain matches: false, invert: false
```

##Credits

I would like to thank the people behind the nDPI project, as the parsing function is based on their work.
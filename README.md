# DNSAgent
A powerful "hosts" replacement.

## Features

* Use regular expression to match the domain name.
* Both IPv4 and IPv6 are supported.
* Support non-standard listening port (ports other than 53).
* It's possible to use DNSPod HttpDNS protocal to query for A record.
* Return a immediate address (A/AAAA record) or redirect query to a custom name server on pattern matched.
* Redirect one domain name to another, support regular expression matching and replacing.
* Local cache with custom TTL settings.
* Support source IP whitelist to filter unauthorized clients.
* Support compression pointer mutation when querying another name server. This may avoid MITM attack in some network environments.

## Download

You can always get the latest release here: https://github.com/stackia/DNSAgent/releases/latest

### Requirement

* .NET Framework 4.5+ (not compatible with Windows XP)

## For Dnsmasq Users

There is a Dnsmasq to DNSAgent rules converter available to quickly make your Dnsmasq rules working with this program:

https://stackia.github.io/masq2agent/

## Usage

Edit `options.cfg` to change options.

Edit `rules.cfg` to customize your rules.

Both `options.cfg` and `rules.cfg` are standord JSON files, your can use any of your favorite editors to open them.

Launch `DNSAgent.exe` and **change your system DNS to 127.0.0.1**. Voilà!

## Configuration

You can choose to install DNSAgent as a Windows service by running `Install as Service.bat`. And `Uninstall Service.bat` to remove this service.

A sample configuration:

### options.cfg:
```
{
    "HideOnStart": false,
    "ListenOn": "127.0.0.1:53, [::1]",
    "DefaultNameServer": "119.29.29.29",
    "UseHttpQuery": false,
    "QueryTimeout": 4000,
    "CompressionMutation": false,
    "CacheResponse": true,
    "CacheAge": 86400,
    "NetworkWhitelist": null
}
```

Set `CacheResponse` to `false` will disable local cache. Set CacheAge to 0 will use the DNS response's record TTL as cache TTL.

Set `UseHttpQuery` to `true` will use [DNSPod HttpDNS](https://www.dnspod.cn/httpdns/demo) procotal to query the name server. HttpDNS protocol doesn't support IPv6.

If you want to filter source IP, you can set `NetworkWhitelist` with the following format ([CIDR notation](http://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing) is used below):
```
    "NetworkWhitelist": [
        "127.0.0.1/32",
        "192.168.199.0/24"
    ]
```
WARNING: Set `NetworkWhitelist` to `[]` will deny all requests. If you want to disable source IP filting, set `NetworkWhitelist` to `null`.

### rules.cfg:
```
[
    {
        "Pattern": "^(.*\\.mydomain\\.com)|((.*\\.)?(yourdomain|hisdomain)\\.com)$",
        "Address": "112.223.221.26"
    },
    {
        "Pattern": "^www\\.google\\.com\\.hk$",
        "Address": "www.google.com",
        "NameServer": "8.8.4.4",
        "CompressionMutation": true
    },
    {
        "Pattern": "^(.*)\\.mysuffix\\.com$",
        "Address": "{1}"
    },
    {
        "Pattern": "^www\\.google\\.com\\.tw$",
        "Address": "www.google.com",
        "NameServer": "127.0.0.1"
    },
    {
        "Pattern": "^www\\.google\\.co\\.jp$",
        "Address": "www.google.com"
    },
    {
        "Pattern": "^www\\.google\\.cn$",
        "NameServer": "114.114.114.114"
    },
    {
        "Pattern": "^.*\\.cn$",
        "NameServer": "119.29.29.29",
        "UseHttpQuery": true,
        "QueryTimeout": 1000
    }
]
```

When a domain name matchs mutiple rules, the last one is used.

You can use {0}/{1}/{2}/... to insert regular expression group matches in "Address" field.

IPv6 address will only be returned when the client querys for AAAA records.

`ListenOn` / `DefaultNameServer` / `NameServer` field can be of following formats:

```
127.0.0.1 // IPv4 address with a default port 53
127.0.0.1:9029 // IPv4 address with a custom port 9029
2001:4860:4860::8888 // IPv6 address with a default port 53
[2001:4860:4860::8888]:9029 // IPv6 address with a custom port 9029
```

You can press `Ctrl + R` to reload all configurations and clear cache without restart this program.

# License

The project is released under [MIT License](https://github.com/stackia/DNSAgent/blob/master/LICENSE).

The project uses a modified version of [ARSoft.Tools.Net](http://arsofttoolsnet.codeplex.com/), which is released under [Apache License 2.0](http://arsofttoolsnet.codeplex.com/license). [The modification](https://github.com/stackia/DNSAgent/blob/master/ARSoft.Tools.Net/Dns/DnsMessageBase.cs#L865) enables compression pointer on DNS questions, which shouldn't be done normally according to RFC, but it can be used to bypass DNS poisoning under certain environments.

ARSoft.Tools.Net is an excellent DNS library purely written in C#. Thanks to their great work for .NET community!
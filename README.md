# DNSAgent
A powerful "hosts" replacement.

## Features

* Use regular expression to match the domain name.
* Both IPv4 and IPv6 are supported.
* Return a immediate address (A/AAAA record) or redirect query to a custom name server on pattern matched.
* Support compression pointer mutation when querying another name server. This may avoid MITM attack in some network environments.

## Requirement

* .NET Framework 4.5+ (not compatible with Windows XP)

## For Dnsmasq Users

There is a Dnsmasq to DNSAgent rules converter available to quickly make your Dnsmasq rules working with this program:

https://stackia.github.io/masq2agent/

## Usage

Edit `options.cfg` to change options.

Edit `rules.cfg` to customize your rules.

Both `options.cfg` and `rules.cfg` are standord JSON files, your can use any of your favorite editors to open them.

Launch `DNSAgent.exe` and change your system DNS settings to 127.0.0.1. Boom!

A sample configuration:

options.cfg:
```
{
    "ListenOn": "127.0.0.1:53",
    "DefaultNameServer": "8.8.8.8:53",
    "QueryTimeout": 4000,
    "CompressionMutation": true
}
```

rules.cfg:
```
[
    {
        "Pattern": "^(.*\\.googlevideo\\.com)|((.*\\.)?(youtube|ytimg)\\.com)$",
        "Address": "203.66.168.119"
    },
    {
        "Pattern": "^.*\\.cn$",
        "NameServer": "114.114.114.114:53",
        "QueryTimeout": 1000,
        "CompressionMutation": false
    },
    {
        "Pattern": "baidu\\.com$",
        "Address": "127.0.0.1"
    },
    {
        "Pattern": "www\\.facebook\\.com$",
        "Address": "2a03:2880:f003:b01:face:b00c:0:1"
    },
    {
        "Pattern": "www\\.facebook\\.com$",
        "Address": "31.13.69.144"
    }
]
```

When a domain name matchs mutiple rules, the last one is used.

IPv6 address will only be returned when the client querys for AAAA records.

`ListenOn` / `DefaultNameServer` / `NameServer` field can be of following formats:

```
127.0.0.1 // IPv4 address with a default port 53
127.0.0.1:9029 // IPv4 address with a custom port 9029
2001:4860:4860::8888 // IPv6 address with a default port 53
[2001:4860:4860::8888]:2064 // IPv6 address with a custom port 9029
```

You can press R to reload all configurations without restart this program.
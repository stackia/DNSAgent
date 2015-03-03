# DNSAgent
A powerful "hosts" replacement.

## Features

* Use regular expression to match the domain name.
* IPv4 and IPv6 supported.
* Return a immediate address (A/AAAA record) or redirect query to a custom name server on pattern matched.

## Usage

Edit `rules.cfg` to customize your rules. `rules.cfg` is a standord JSON file, your can use any of your favorite editors to open it.

Launch `DNSAgent.exe` and change your system DNS settings to 127.0.0.1. Boom!

A sample configuration:

```
[
    {
        "Pattern": "^.*$",
        "NameServer": "8.8.8.8"
    },
    {
        "Pattern": "^(.*\\.googlevideo\\.com)|((.*\\.)?(youtube|ytimg)\\.com)$",
        "Address": "203.66.168.119"
    },
    {
        "Pattern": "^.*\\.cn$",
        "NameServer": "114.114.114.114"
    },
    {
        "Pattern": "baidu.com$",
        "Address": "127.0.0.1"
    }
]
```

This configuration respawns Youtube in China and make all querys to .cn domain requested from 114.114.114.114, but *baidu.com is blocked. All other querys are redirected to 8.8.8.8.

When a domain name matchs mutiple rules, the last one is used.
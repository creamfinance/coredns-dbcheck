# CoreDNS DB Check

This plugin allows CoreDNS to check PTR, A and AAAA in a postgres database.

## Installation

Compile CoreDNS with the edited middleware.cfg

```
140:dnssec:dnssec
141:dbcheck:github.com/creamfinance/coredns-dbcheck
150:reverse:reverse
```

## Configuration

Add the following section to your config file to enable the plugin.

```
   dbcheck {
      fallthrough
      database postgres
      connection_string postgres://coredns:coredns@127.0.0.1/coredns?sslmode=disable
   }
```

## DB Setup

Execute the provided db.sql file.

## Merge Requests

Merge requests for:

- additional type handling
- multi value handling
- dynamic tables (without the fixed structure)
- database support (for mysql, oracle, etc)

 are welcome. 

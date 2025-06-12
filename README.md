# PDNS Grep

Search through PowerDNS records via API.

The wildcard `*` can be used as a placeholder in search_term and the `?` character can be used as a placeholder for a single character.

## Installation

Under [Releases](https://github.com/akquinet/pdnsgrep/releases) the binary can be downloaded directly.

Alternatively, you can install it with go: `go install github.com/akquinet/pdnsgrep@latest`

## Configuration

### Environment variables

```bash
export PDNSGREP_URL="https://pdns.example.domain"
export PDNSGREP_TOKEN="your-api-token"
```

### Config file

A config file can be created under `$HOME/.pdnsgrep.yaml` or selected via `--config`.

```yaml
---
url: "https://pdns.example.domain"
token: "your-api-token"
debug: false
verbose: false
```

## Usage

### Help

```bash
pdnsgrep --help
```

### Record

```bash
❯ pdnsgrep "sub.example.domain"
Zone            Name              Type  Content         TTL
example.domain. sub.example.domain. A   [IPv4 Address]  300
```

### IP

```bash
❯ pdnsgrep "10.187.102.42"
Zone             Name                 Type  Content         TTL
example2.domain. sub.example2.domain. A     [IPv4 Address]  300
example.domain.  sub.example.domain.  A     [IPv4 Address]  300
```

### Multiple records

```bash
❯ pdnsgrep "fw" "fw*"
Zone            Name                      Type  Content          TTL
example.domain. fw.example.domain.        A     [IPv4 Address]   3600
example.domain. fw-ham-1.example.domain.  A     [IPv4 Address]   3600
example.domain. fw-ham-1.example.domain.  AAAA  [IPv6 Address]   3600
```

### Only specific record types

```bash
❯ pdnsgrep "lab-asa" --type AAAA
Zone       Name                             Type   Content          TTL
example.domain. lab-asa-01.example.domain.  AAAA   [IPv6 Address]   3600
example.domain. lab-asa-02.example.domain.  AAAA   [IPv6 Address]   3600
```

### Disable colored output

```bash
❯ pdnsgrep "fw" --no-color
```

### Piping into less

```bash
❯ pdnsgrep "*firewall*" | less -S
```

### Get only the names

```bash
❯ pdnsgrep "fw" --output raw --no-header | cut -d' ' -f 2 | sort -u
fw-01.example.domain
fw-02.example.domain.
```

### CSV Export

```bash
❯ pdnsgrep "fw" --output csv
Zone;Name;Type;Content;TTL;Object Type
example.domain.;fw-1.example.domain.;AAAA;IPv6 Address;3600;record
example.domain.;fw-1.example.domain.;A;IPv4 Address;3600;record
....
```

### JSON Export

```bash
❯ pdnsgrep "fw" --output json
[
  {
    "name": "fw-1.example.domain.",
    "type": "A",
    "content": "[IPv4 Address]",
    "object_type": "record",
    "zone": "example.domain.",
    "ttl": 3600
  },
  ...
]
```

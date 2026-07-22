# Iterative DNS Resolver

A DNS message parser and iterative DNS resolver written in Python for the
UNSW COMP3331/9331 Computer Networks and Applications assignment.

The resolver starts from a root hints file, follows DNS referrals without
requesting recursion from upstream servers, chases CNAME records, and returns
UDP responses to clients on the IPv4 loopback interface. It uses only the
Python standard library.

## Features

- Parses DNS headers, questions, and resource-record sections from wire-format
  messages.
- Decodes compressed domain names and validates malformed pointers, labels,
  lengths, and RDATA boundaries.
- Resolves `A`, `NS`, `CNAME`, `MX`, and `PTR` queries iteratively.
- Follows referrals using in-bailiwick glue and resolves name-server addresses
  when glue is unavailable.
- Chases CNAME chains while detecting loops and enforcing a chain limit.
- Handles authoritative answers, NODATA, and NXDOMAIN responses.
- Caches complete positive answers with decreasing TTLs.
- Serves overlapping client requests with worker threads.
- Answers root NS and root-server A queries directly from the root hints file.
- Compresses names in client responses and enforces the 512-byte UDP response
  limit.

## Requirements

- Python 3.10 or later
- Network access to authoritative DNS servers over UDP port 53 for live
  resolution

No third-party packages are required.

## Run the resolver

From the repository root:

```sh
python3 resolver.py <root_hints_file> <timeout_seconds> <listen_port>
```

For example:

```sh
python3 resolver.py src/named.root 2 8053
```

The server listens on `127.0.0.1` using UDP. Use an unprivileged port such as
`8053` unless your environment permits binding to privileged ports.

Query it with a DNS client such as `dig`:

```sh
dig @127.0.0.1 -p 8053 example.com A
dig @127.0.0.1 -p 8053 example.com MX
dig @127.0.0.1 -p 8053 . NS
```

The timeout argument is the maximum wait for each upstream server attempt.
Each complete lookup is also bounded by the resolver's attempt, referral, and
wall-clock limits. Stop the server with `Ctrl-C`.

## Inspect a DNS message

`parser.py` prints the contents of a binary DNS query or response:

```sh
python3 parser.py <dns-message-file>
```

Sample messages are included in `src/`:

```sh
python3 parser.py src/example.com-MX-12002-response.bin
```

The output includes header flags, section counts, questions, answers,
authority records, and additional records. Unknown record types are skipped
using their declared RDLENGTH and displayed as metadata.

## Run the tests

The test suite is deterministic and does not contact public DNS servers:

```sh
python3 -m unittest discover -s test -v
```

It covers parsing, encoding, root hints, referral and CNAME handling, caching,
upstream validation, resolution limits, and concurrent UDP server behavior.
These tests supplement rather than replace the course marking suite; live
network behavior still depends on the execution environment.

## Project structure

```text
.
├── resolver.py              # UDP server and client request handling
├── parser.py                # DNS message inspection CLI
├── cache.py                 # Thread-safe positive-answer cache
├── constants.py             # DNS and resolver limits/constants
├── root_hints.py            # Root hints parser
├── dns/
│   ├── message.py           # Wire-format decoder
│   ├── encoder.py           # Query and response encoder
│   └── records.py           # DNS data models
├── resolver_core/
│   ├── iterative.py         # Iterative resolution and CNAME traversal
│   ├── upstream.py          # Upstream UDP queries and validation
│   ├── helpers.py           # Referral, answer, and root-hint helpers
│   └── models.py            # Per-resolution resource budget
├── src/                     # Root hints and sample DNS messages
└── test/                    # Specification-oriented unit tests
```

## Scope and limitations

- Client and upstream transport is UDP over IPv4 only.
- Truncated upstream responses are rejected; TCP fallback is not implemented.
- Client responses are limited to the classic 512-byte DNS UDP size.
- EDNS, DNSSEC validation, IPv6 resolution, and negative caching are outside
  the current scope.
- Only one question per client request is supported. Unsupported query types
  receive `SERVFAIL`.

## Root hints format

The root hints parser accepts the assignment's zone-file subset: `$TTL`
directives plus `IN NS` and `IN A` records. Comments beginning with `;` are
ignored. A sample file is available at `src/named.root`.

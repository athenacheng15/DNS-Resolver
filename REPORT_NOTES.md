# COMP3331 DNS Resolver Report Notes

## 1. Code Organisation

### parser.py

- Provides the Stage 1 command-line interface.
- Reads a binary DNS message and prints its decoded contents.

### dns_message.py

- Contains low-level DNS message decoding functions.
- Parses headers, questions, names, compression pointers, and resource records.
- Supports A, NS, CNAME, PTR, and MX RDATA.

### dns_records.py

- Defines the DNSHeader, DNSQuestion, ResourceRecord, and DNSMessage classes.
- Contains mappings for DNS types, classes, and response codes.

### root_hints.py

- Parses the supplied named.root file.
- Handles blank lines, comments, $TTL, optional TTL and IN fields.
- Stores root NS and IPv4 A records while preserving file order.

### dns_encoder.py

- Encodes DNS headers, questions, names, resource records, and responses.
- Constructs the Answer, Authority, and Additional sections.
- Calculates section counts from the records actually encoded.

### resolver.py

- Provides the resolver command-line interface.
- Opens a UDP socket on 127.0.0.1 and the requested listen port.
- Receives client queries and returns Stage 2 root-hints-local responses.

## 2. Data Structures

### DNSHeader

Stores the DNS transaction ID, flags, and section counts.

### DNSQuestion

Stores QNAME, QTYPE, and QCLASS for one DNS question.

### ResourceRecord

Stores owner name, type, class, TTL, RDLENGTH, and decoded RDATA.

### Root NS Records

A list of ResourceRecord objects preserving the order of NS records in named.root.

### Root A Records

A list of ResourceRecord objects preserving the order of A records in named.root.

### Root A Map

A dictionary mapping a normalised root-server name to a list of matching A records.

Example:

```text
"a.root-servers.net." -> [ResourceRecord(...)]
```

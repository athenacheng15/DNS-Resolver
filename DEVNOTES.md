# Resolver Workflow

## Startup (runs once)

```
named.root (DNS Zone File)
    --> root_hints.py (Text Parser)
    --> ResourceRecords (stored in memory)
```

The resolver loads and parses `named.root` once at startup.
All root NS and A records are stored in memory for future queries.

---

## Query Handling (runs for every query)

```
Client
    --> Binary DNS Query
    --> Resolver
    --> Lookup ResourceRecords
    --> Build Binary DNS Response
    --> Client
```

The resolver looks up matching records in memory and constructs a binary DNS response.

## DNS Header Flags

The DNS header stores all flags inside a single 16-bit integer rather than as separate values.

```text
bit 15        11       10  9   8   7          4  3       0
+---+----------+---+---+---+---+-------------+-----------+
|QR | OPCODE   |AA |TC |RD |RA | Z / AD / CD | RCODE     |
+---+----------+---+---+---+---+-------------+-----------+
```

Bitwise OR combines the fields into one 16-bit flags value.

```
flags |= 1 << 15
```

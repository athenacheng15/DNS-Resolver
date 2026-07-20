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

## CNAME Resolution

### CNAME Response Parsing

- `extract_cname_chain_and_final_answers()` examines the Answer section of one upstream DNS response.
- It follows CNAME records in order until:
  - the requested record type is found;
  - no further CNAME exists;
  - a CNAME loop is detected; or
  - the maximum CNAME limit is exceeded.
- The function returns:
  - the ordered CNAME chain;
  - the final requested-type answers;
  - the terminal canonical name.
- Multiple CNAME records for the same owner are accepted only when they point to the same target.
- Conflicting CNAME targets are treated as an invalid response.
- DNS names are normalised before comparison to support case-insensitive matching.

### Direct CNAME Queries

- A direct `CNAME` query returns only the CNAME RRset owned by the original queried name.
- The resolver must not follow the CNAME target for a direct `CNAME` query.

Example:

```text
Query:
CNAME www.example.com.

Response:
www.example.com. CNAME edge.example.net.
```

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

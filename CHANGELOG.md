# Changelog

## 2026-06-3

- [a693d15] Added DNS lookup tables for record types, classes, and response codes.
- [7d766ea] Added DNS header flag parsing for QR, opcode, AA, TC, RD, RA, and RCODE.
- [7d766ea] Updated parser output to display DNS header fields and decoded response codes.

## 2026-06-29

- [db01b57] Initialized the DNS resolver project and added the initial source files.
- [c1e4f71] Added the initial parser entry point for reading DNS message files.
- [6ede4dc] Added DNS message byte-reading helpers for unsigned integers and raw bytes.
- [52ff56a] Added DNS record model classes for headers, questions, resource records, and messages.
- [75e76f5] Added DNS header parsing and parser output for header fields.

# Changelog

## 2026-07-07

- [0074dce] Added parsing for root hints records.
- [0f5136b] Documented the resolver query workflow.

## 2026-07-05

- [4236e44] Added parser output for DNS resource records.
- [7007350] Reorganized DNS output formatting.
- [ba9edcf] Added safer handling for malformed RDATA.
- [d2d44cb] Fixed A record RDATA offset advancement.
- [58799bf] Simplified the DNS parser output format.

## 2026-07-02

- [a02665e] Added DNS domain name parsing.
- [ea62e42] Added parsing for DNS question sections.
- [1613bbf] Updated parser output to print parsed questions.
- [b246d51] Added support for compressed DNS names.
- [ff243b0] Added DNS resource record and RDATA parsing.

## 2026-06-30

- [a693d15] Added DNS lookup tables for record types, classes, and response codes.
- [7d766ea] Added DNS header flag parsing for QR, opcode, AA, TC, RD, RA, and RCODE.
- [7d766ea] Updated parser output to display DNS header fields and decoded response codes.

## 2026-06-29

- [db01b57] Initialized the DNS resolver project and added the initial source files.
- [c1e4f71] Added the initial parser entry point for reading DNS message files.
- [6ede4dc] Added DNS message byte-reading helpers for unsigned integers and raw bytes.
- [52ff56a] Added DNS record model classes for headers, questions, resource records, and messages.
- [75e76f5] Added DNS header parsing and parser output for header fields.

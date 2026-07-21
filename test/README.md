# DNS resolver specification tests

These tests translate the observable implementation requirements in
`COMP3331_26T2_Assignment_v1.pdf` into deterministic standard-library tests.
They do not contact the public DNS and do not replace the course marking suite.

Run all tests from the repository root:

```sh
python3 -m unittest discover -s test -v
```

Coverage by specification area:

- `test_parser_spec.py`: Sections 9.1-9.4 (CLI, sections, counts, supported and
  unknown RDATA, compression, RDLENGTH boundaries, malformed names).
- `test_root_hints_spec.py`: Sections 10.2-10.4 (accepted file subset, ordering,
  case-insensitive matching, root NS/A local answers).
- `test_encoder_response_spec.py`: Sections 8.3, 11.1, and 11.6 (IDs, flags,
  question preservation, section counts, upstream query shape).
- `test_resolution_helpers_spec.py`: Sections 11.4-11.6 (referral selection,
  glue filtering, NODATA, direct and chained CNAME behavior).
- `test_iterative_resolver_spec.py`: Sections 11.1 and 11.4-11.8 (iterative
  flow, no-glue lookup, terminal responses, cache use, hard limits).
- `test_cache_spec.py`: Section 11.7 (normalised keys, TTL floor/expiry, complete
  CNAME entries, thread safety).
- `test_upstream_spec.py`: Sections 11.1 and 11.8 (response matching, truncation,
  candidate retry order, attempt accounting).
- `test_server_spec.py`: Sections 8.2-8.3, 10.1, and 11.9 (loopback UDP,
  client ID/address isolation, overlapping workers).

The tests intentionally use documentation-style names so a failure points back to
the relevant requirement. Live Internet behavior, VLAB compatibility, performance
measurements, source-code readability, report content, and viva readiness require
separate manual review and cannot be established reliably by this unit suite.

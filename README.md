# biochain-shdccp-core

Canonical 64-bit Einstein Tile: C11 and Python codecs, reference Rust/C#/TypeScript bindings, cross-language vector specification, exact cubic geometry. Production envelope identity and complete form-specific decoders are unfinished.

Integration: contracts are defined by the shared `biochain-shdccp-core` releases. This repository is designed to be split and versioned independently; currently all six roots share a developer umbrella workspace.

Reference command from workspace root: `python -m unittest discover -s ../../tests; make -C ../.. codec`

## RFC 07: the shdccp/2 biochain contract

- [`rfcs/07_shdccp2_contract.md`](rfcs/07_shdccp2_contract.md) specifies the `shdccp/2` biochain stream and record that
  Owl-Academy grows (it is not an Einstein Tile; see its section 14). [`contract_vectors/`](contract_vectors/) holds its
  vectors, generator, drift check and lock.
- RFC 07's text and the `contract_vectors/` folder are CC0-1.0 (a small fragment of `contract_vectors/schema.json`
  copied from SHD-CCP stays MIT); the rest of this repository stays GPL-3.0 ([`NOTICE`](NOTICE)).
- Check them with `python3 -B tools/run_checks.py --owl ../Owl-Academy --biochain ../BioChain-AI` (Node 20 or later,
  an Owl-Academy clone and a BioChain-AI clone); CI also runs the independent oracle (`--lexicon-root`) and the
  immutability check against the base commit (`--base`).

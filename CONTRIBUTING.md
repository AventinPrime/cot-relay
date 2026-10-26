# Contributing

This started as a small, focused tool (see README for scope and known
limitations), not a framework - keep that in mind before proposing large
architectural changes.

## Before opening a PR

- Run the existing test scenarios (there's no formal test suite yet -
  see the "Next steps" section in the README; contributions adding one
  are welcome).
- Keep changes scoped: one feature or fix per PR.
- If you're touching CoT parsing/protocol handling, please link to the
  spec, server documentation, or source you verified it against - this
  project has already had a couple of bugs from unverified assumptions
  about protocol details, and would rather not repeat that.

## Reporting bugs

Open an issue with:
- What server you're connecting to (GoATAK version, or other TAK-family
  server) - protocol behavior isn't identical across implementations.
- The relevant CoT event(s) if you have them (`--verbose` logging helps),
  with anything sensitive (real UIDs, positions, callsigns) redacted.
- What you expected vs. what happened.

## Feature requests

Feel free to open an issue, but no guarantees on timeline - this is
maintained alongside other work, not a full-time project.

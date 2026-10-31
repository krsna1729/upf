# Notes for coding agents

Read [docs/engineering-guide.md](docs/engineering-guide.md) before you
change code. It lists the rules that review and the lanes enforce, each with
the commit or finding behind it. The datapath plugin also follows the BESS
fork's
[engineering guide](https://github.com/krsna1729/bess/blob/develop/docs/engineering-guide.md).

The most frequent misses, in order of cost:

1. **Scale.** A change to a table, queue, loop over sessions, tick or packet
   path runs the scale review checklist (guide §8). Cost follows what
   changed; prove it with a count, not a time.
2. **The engine's rules.** One operation per (resource, key) per
   transaction, released ids wait out the grace period, and a refused
   establishment frees its ids (guide §4). The unit-test recorder does not
   enforce these; a live lane does.
3. **The spec.** Read and quote the clause from `docs/spec/`; never cite
   from memory. upfd stays strict; peer-tool bugs go upstream (guide §3).
4. **Lanes.** Scratch under TMPDIR (default `build/run`), never `/tmp`;
   socket paths fit 108 bytes; root lanes need a work dir outside a private
   home (guide §5). Run the lane that proves the path you touched
   (README.md).
5. **Evidence.** Each claim names its check; write `[INFERENCE]` for the
   rest. Never report a number you did not measure (guide §6).
6. **Pull requests.** A fix is its own PR, separate from features; a PR on
   an unmerged BESS pin says so in its title and does not merge (guide §7).

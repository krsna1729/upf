# 3GPP specifications

This directory holds excerpts of the specification clauses this tree's claims cite. The register
in `docs/claims.json` names, for every claim, the specification, release
version and clause it reads; this directory is the text those references point
at.

The pinned release is **3GPP Release 16**, the newest release whose PFCP
feature set this tree supports. The parser and compiler are exercised against
this text. `go-pfcp` (our `v0.0.25-upf.4` fork) implements the same release's PFCP IEs; its own
conformance statement names TS 29.244 V16.7.0, while the claims below cite the
final V16.9.1 revision for the exact clauses. Later releases are not copied or
cited: their clauses may add fields or change conditions this tree has not
implemented, and a newer text is not evidence for this implementation.

| Specification | Version | File | Official source |
|---|---|---|---|
| TS 29.244 — Interface between the Control Plane and the User Plane Nodes | 16.9.1 | `29.244-v16.9.1.txt` | https://www.3gpp.org/ftp/Specs/archive/29_series/29.244/29244-g91.zip |
| TS 29.281 — GPRS Tunnelling Protocol User Plane (GTPv1-U) | 16.2.0 | `29.281-v16.2.0.txt` | https://www.3gpp.org/ftp/Specs/archive/29_series/29.281/29281-g20.zip |
| TS 38.415 — PDU Session User Plane Protocol | 16.6.0 | `38.415-v16.6.0.txt` | https://www.3gpp.org/ftp/Specs/archive/38_series/38.415/38415-g60.zip |

The archive and excerpt hashes make the copies checkable:

| Specification | Archive SHA-256 | Excerpt SHA-256 |
|---|---|---|
| TS 29.244 V16.9.1 | `88c0e4d30643bb49403214c09c749bd4c70da0ecbd32f6c9eb182b995da4dac7` | `7c94676f9eac29022a3436a5daeac8dd15478145715fa5f91640c69a890dec8e` |
| TS 29.281 V16.2.0 | `1cd5d70ebbe60393c215cf259196e7ac18622bea540c8c12d80fefceb10fdece` | `83849f824e84a8c4aa513fdfd43e3b64d7f123b678b496eb60840d45179d0edc` |
| TS 38.415 V16.6.0 | `0a54fa84efb85eb7c377160e4458cb8cf90f91cce57f5598fd5f06da4c7c9f6f` | `e81aac78132d777a6c3d58f8648a3012ea382917c361bd1789101be5780a3d84` |

The `.txt` files are excerpts: the cited clause headings and body text, cut
from the official 3GPP `.docx`/`.doc` archives converted to UTF-8 with
LibreOffice (`--convert-to 'txt:Text (encoded):UTF8'`). 3GPP does not publish a
plain-text edition of these specifications: the archive holds `.docx` (or
`.doc`) only. The archive hash and excerpt hash above make the provenance
checkable; the table of contents, page breaks and uncited clauses are omitted.
They are reference copies, not a second source of truth: the specification
number, version and clause in a claim identify the text. Page numbers and line breaks are LibreOffice's and are not stable; cite
clauses, never line numbers.

**Audit within the pinned release.** `go-pfcp` names TS 29.244 V16.7.0 as its
conformance baseline, so the 15 clauses this tree cites there were compared
between V16.7.0 and the pinned V16.9.1. Thirteen are identical after
whitespace normalization; 7.5.4 differs only by a missing space. 5.2.1
gained one new normative requirement -- every PDR must carry enough
information to identify its PFCP session (Traffic Endpoint Identifier, or
equivalent such as the UE address or local F-TEID) -- and reworded the
look-up steps without changing the rule this tree implements. The compiler
already enforces the new requirement: an uplink PDR must name the F-TEID the
decap writes, and a downlink PDR is keyed by the session's UE address (see
`status-25` and `status-37`). The remaining specifications are pinned at
their latest Release 16 revision, so there is no later revision in the
released baseline to audit.

**Newer releases, not claimed.** The newest published revisions on 2026-10-20
are TS 29.244 V20.1.0, TS 29.281 V19.2.0, TS 38.415 V19.1.0, TS 23.501
V20.3.0 and TS 23.502 V20.3.0. They are not vendored, cited or tested here.
The cited clauses do differ from the pinned Release 16 text: for example,
nearly every cited TS 29.244 clause gained N4mb columns, flags or optional
IEs in later releases. That is why "latest" is not automatically the right
pin: a newer clause can change a condition this implementation has not
implemented. The check is against the pinned release, and a move to a newer
release is a separate implementation and audit.

**Textual change audit.** The 15 TS 29.244 clauses this tree cites were
compared over the later releases (whitespace and `[n]` reference markers
normalized). The counts below are textual, not a support statement: much of
the growth is the repeated `N4mb` column and MBS parameters in large IE
tables.

| Release | Cited clauses changed | Words added / removed | Main additions |
|---|---|---|---|
| 17 | 11 of 15 | +5,091 / -133 | MBS and the N4mb interface, DNS Query Filter, URR User Plane Inactivity Timer and Quota Action, Apply Action FSSM/MBSU |
| 18 | 8 of 15 | +3,001 / -160 | MPTCP expanded to Multipath/MPQUIC, HR-SBO mapped N6 IP/routing, Forwarding Policy metadata, MAR Redundant steering |
| 19 | 13 of 15 | +3,799 / -95 | PDU Set marking, transport level marking, SDF Filter SMMII, MPQUIC-E, ePDG/TWAN FQ-CSID; several other diffs are only "3GPP TS"→"TS" cleanup |
| 20 | 3 of 15 | +175 / -26 | SCONE marking, start pause of charging, PDU Set Importance for N6-unmarked PDUs |

The other cited clauses changed very little: TS 29.281 7.3.1 gained
"Recovery Time Stamp" in Release 17 and is otherwise stable through 19;
TS 38.415 5.5.3.3 (QFI) is identical from 16 through 19. None of the later
additions is implemented or claimed. The table shows why a pin can be the
latest revision of a release while still being far from the latest
published text.

**Release policy.** A claim may cite a clause only from the pinned release
above. A newer release's clause is not evidence for this tree: it may add
fields or change a condition, and the compiler's behaviour is defined against
the pinned text. Moving the pin is a deliberate change to every affected
claim, the claim register's `specs` map, and the tests that cite it. There is
no implicit "latest" anywhere in the register.

The official 3GPP specification pages are at
https://www.3gpp.org/specifications-technologies/specifications-by-series;
the archives above are the 3GPP FTP `Specs/archive` copies. 3GPP specifications
are copyright their Organizational Partners; these copies are included as the
references the claims are checked against.

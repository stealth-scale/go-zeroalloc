<!--
  ~ Copyright Stealth Scale B.V. 2026
  ~ SPDX-License-Identifier: MIT
-->

# Documentation

Where each kind of document is kept, and which one to write.

| Directory | Contains | Write one when |
|---|---|---|
| `architecture/` | How the system is put together, kept current | Someone needs to place a file or trace a dependency |
| `roadmap/` | What we build in what order, and what has to be true first | Work needs sequencing rather than justifying |
| `rfc/` | Proposals and the argument behind them | A change alters a contract, or several approaches are worth comparing |
| `adr/` | Decisions already made, and what they cost | One decision is settled and no credible alternative is still open |

Milestone numbers are in `roadmap/` and nowhere else.

Edit a document in `architecture/` in the same commit as the change it describes. An RFC keeps its argument after it is accepted or rejected. To change a decision an ADR records, write a new ADR and mark the old one superseded.

<!--
  ~ Copyright Stealth Scale B.V. 2026
  ~ SPDX-License-Identifier: MIT
-->

# Contributing to go-zeroalloc

## The gate

`make check` runs the formatters, the linters and the tests of every language of the repository.
CI runs the same targets on every pull request, so a change that passes `make check` locally
passes the gate in CI.

## Changes

- Open a pull request against `main`.
- Add a changeset to `.changeset/` for each change that a release contains.
- Write each commit message as a Conventional Commit: `type(scope): subject`.

## Conduct

Every contributor follows the [Code of Conduct](CODE_OF_CONDUCT.md).

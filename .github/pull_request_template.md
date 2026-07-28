## What does this PR do?

<!-- One paragraph. What changed and why. -->

## Type of change

- [ ] Bug fix
- [ ] New feature / credential type
- [ ] Refactor / cleanup
- [ ] Docs
- [ ] CI / tooling

## Merge requirements

- [ ] **CI is green** — `cargo test` (contracts), `pnpm tsc --noEmit` (frontend), `pnpm build` (frontend), circuit tests — all green
- [ ] **Greptile confidence ≥ 4/5** — all review comments addressed, no unresolved threads
- [ ] Circuit changes: `fixtures/<type>/` artifacts updated
- [ ] No `NEXT_PUBLIC_` prefix on server-only env vars
- [ ] No identity fields stored or logged after KYC provider call

## Notes for reviewers

<!-- Anything tricky, a design decision you're unsure about, or context that isn't obvious from the diff. -->

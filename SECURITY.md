# Security Policy

NEX is a capability-safe execution language. Security is a first-class invariant.

## Supported Versions
We currently support security fixes for the latest tagged release and `main`.

## Reporting a Vulnerability
Please do NOT open a public issue for vulnerabilities.

Instead:
1. Go to the GitHub Security tab for this repository
2. Create a **Private Security Advisory**
3. Include:
   - minimal repro `.nex`
   - commands to run
   - expected vs actual behavior
   - impact analysis (authority escalation? nondeterminism? sandbox escape?)

## What Counts as a Vulnerability
Examples:
- Capability enforcement bypass
- Effect typing bypass
- Path traversal not blocked as specified
- Net listen policy bypass
- Orphan task leaks / broken structured concurrency cleanup
- Codegen producing behavior that contradicts static policy

## Response Targets
We aim to acknowledge reports quickly and publish fixes with a tagged release.


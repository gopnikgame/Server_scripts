# Shell supply-chain safety

## Network downloads

Do not pipe remote content directly into a privileged shell. Download into a restrictive temporary directory, inspect/verify, and invoke an explicit local path.

For release artifacts:

1. Resolve a pinned version or record the exact immutable commit/release selected.
2. Download over HTTPS with failure-on-HTTP-error and bounded timeouts.
3. Verify the publisher's signature or checksum from an independently authenticated source when available.
4. List archive members and reject absolute paths, `..` traversal, special devices, and unexpected top-level layout before extraction.
5. Extract without inheriting unsafe ownership.
6. Run version/config checks on the candidate.
7. Preserve the previous working binary and replace atomically.

Treat `latest` endpoints as discovery, not integrity. Do not invent a checksum when the publisher does not provide one; state the missing assurance.

## Git and mirrors

- Keep upstream and mirror roles explicit.
- Fetch before claiming synchronization.
- Mirror branches, tags, and required LFS/submodules deliberately.
- Verify the destination ref after push.
- Do not embed credentials in repository URLs or logs.
- Provide a Forgejo/internal fallback for bootstrap assets when loss of GitHub access is in scope.

## External installers

Read the installer at the exact downloaded revision, identify its mutations and update channel, and decide whether to vendor/pin it or reproduce its documented steps. A trusted project name does not make `curl | bash` safe.

## Official sources

- curl security considerations: https://curl.se/docs/security.html
- Git object integrity: https://git-scm.com/book/en/v2/Git-Internals-Git-Objects
- OpenSSF Scorecard checks: https://github.com/ossf/scorecard/blob/main/docs/checks.md

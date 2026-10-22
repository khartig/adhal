# Dependency policy

What to do when a dependency has a known vulnerability, and the rules for
adding or changing one. This is the gating half of Q-08
([`SECURITY-REVIEW.md`](SECURITY-REVIEW.md)). The rest of Q-08 is the
SBOM, attached to each GitHub Release, and signed releases, which are not
done yet.

A vulnerability in Adhal's own code goes through
[`SECURITY.md`](../SECURITY.md), not this document.

## What fails the build

Two CI jobs in `.github/workflows/ci.yml` check `pnpm-lock.yaml`, and both
are required:

| Job | Database | Fails on |
| --- | --- | --- |
| `audit` | GitHub Advisory Database, through `pnpm audit --audit-level moderate` | moderate, high, or critical |
| `osv-scanner` | OSV, which takes in GitHub's advisories and adds other sources, including reports of malicious packages | any finding, low severity included, since the scanner has no threshold |

Both check the whole lockfile: the engine's and CLI's dependencies, the
packages those pull in, and the workspace's dev dependencies. Most of the
lockfile is the Holepunch tree under `hyperswarm` and `hyperdht`, so most
findings will be transitive.

To run them locally:

```sh
pnpm audit --audit-level moderate
docker run --rm -v "$PWD":/src:ro ghcr.io/google/osv-scanner-action:v2.7.0 \
  scan source --config=/src/osv-scanner.toml --lockfile=/src/pnpm-lock.yaml
```

## When a scan finds something

Take the first response that applies.

1. **A fixed version exists. Upgrade to it.** For a direct dependency,
   change its exact pin in `engine/package.json` or `cli/package.json`.
   For a transitive one, first upgrade the direct dependency that pulls
   it in, if a release of that dependency takes the fix. If none does
   yet, force the fixed version with an `overrides` entry in
   `pnpm-workspace.yaml`. Give the entry a comment naming the advisory,
   and remove it once the direct dependency catches up. Then run the full
   suite, since an override puts a version under the Holepunch stack that
   its authors did not test against.
2. **No fix exists, and Adhal cannot reach the vulnerable code.** Add an
   exception (below).
3. **No fix exists, and Adhal can reach the vulnerable code.** Then Adhal
   has the vulnerability, and it goes through [`SECURITY.md`](../SECURITY.md)
   as a report against Adhal. That means a fix or workaround in Adhal's
   code, a release, a GitHub security advisory, and `npm deprecate` on the
   affected versions. An exception may hold the build open while that
   happens, but its reason must name the advisory Adhal is preparing.

**A report of a malicious package is never an exception.** OSV lists
these with `MAL-` IDs. Remove the package and regenerate the lockfile.
Then find out whether any published release of `@ad-hal/engine` or
`@ad-hal/cli` resolved to it. If one did, it goes through SECURITY.md
like case 3.

When it is not clear whether Adhal can reach the vulnerable code, treat
it as case 3.

## Exceptions

An exception lets the build pass with a known advisory in the lockfile.
Each one needs:

- **The advisory's ID.** Use the GHSA ID where there is one. It goes in
  `osv-scanner.toml` as an `[[IgnoredVulns]]` entry, and, if
  `pnpm audit` reports it too, in `auditConfig.ignoreGhsas` in
  `pnpm-workspace.yaml`:

  ```toml
  # osv-scanner.toml
  [[IgnoredVulns]]
  id = "GHSA-xxxx-xxxx-xxxx"
  ignoreUntil = 2027-01-19
  reason = "Which package and path, why Adhal never reaches it, and how that was checked."
  ```

  ```yaml
  # pnpm-workspace.yaml
  auditConfig:
    ignoreGhsas:
      # Until 2027-01-19. Reason in osv-scanner.toml.
      - GHSA-xxxx-xxxx-xxxx
  ```

- **A reason that can be checked.** Name the vulnerable package and
  function, the path by which it is in the lockfile, and why Adhal never
  calls it. Then say how that was established: which code was read, or
  what was run. "Transitive" and "not used" are not reasons on their own.
  A false positive, such as an advisory that names the wrong version
  range, is an exception too, and its reason links the evidence.
- **An expiry no more than 90 days out.** `ignoreUntil` enforces it. Once
  the date passes, `osv-scanner` fails again, and the exception has to
  be removed or renewed with its reason checked again. `pnpm audit` has
  no expiry, so the date goes in a comment beside the ID, and the two
  are renewed or removed together.
- **A commit of its own.** The message names the advisory, so the
  exception can be found in the history and reviewed on its own.

When the fixed version arrives, upgrade and remove the exception from
both files in the same commit.

## Adding or changing a dependency

- **Pin it exactly.** Use `1.2.3`, not `^1.2.3`. The engine and CLI pin
  every dependency this way. The two dev dependencies in the root
  `package.json` still use ranges. They never ship, but the lockfile
  pins them all the same.
- **Say why it is needed** in the commit message. Every package in the
  engine's dependencies ships to every user.
- **Read the lockfile diff,** not only the `package.json` change. One
  new dependency can bring in many packages.
- **Allow no install scripts.** pnpm 10 and later block dependency
  install scripts by default, and this repository allows none. Allowing
  one is a change to this policy, not a routine edit.
- **Both scans pass** before it merges, like any other change.

## Before a release

- Both scans pass on the commit being tagged.
- The release notes list every exception in force, each with its
  advisory, its reason, and its expiry.

## What this does not cover yet

- **Advisories published after a merge.** The scans run on pushes and
  pull requests. An advisory published against a lockfile nobody has
  changed goes unseen until the next run. A scheduled run would close
  that gap.
- **Provenance of the native modules.** `udx-native` and
  `sodium-native` ship prebuilt binaries. `pnpm audit signatures`
  verifies the registry signatures of all 101 packages, but nothing in
  CI runs it yet, and a registry signature says what npm received, not
  how the binary inside it was built.
- **Signed releases**, the rest of Q-08. The SBOMs are built by
  `.github/workflows/release.yml`, one CycloneDX file per package,
  attached to each GitHub Release. They list the locked tree, which a
  user's install can differ from, as that file explains.

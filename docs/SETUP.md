# Setup

## Prerequisites

- Node.js >= 18 (developed against v22.11.0 via nvm). Check with `node -v`.
- [pnpm](https://pnpm.io) (developed against 12.4.1). Install with
  `npm install -g pnpm`, or via Corepack if your Corepack install can reach
  npm's registry (`corepack enable && corepack prepare pnpm@12.4.1 --activate`).
  If Corepack fails with a `Cannot find matching keyid` signature error,
  its bundled key set is stale -- skip it and install pnpm directly with
  `npm install -g pnpm` instead (remove any existing corepack pnpm/pnpx
  shims first if you hit `EEXIST`).
- git, and the [GitHub CLI](https://cli.github.com/) (`gh`) if you want to
  work with pull requests/issues from the terminal.

## Getting the code running

```bash
git clone <repo-url> quay
cd quay
pnpm install            # installs root + engine + cli workspaces in one pass
pnpm test               # runs the item-1 loopback proof automatically
pnpm run demo:loopback  # runs it manually; prints both sides' output live
```

`pnpm install` at the repo root installs dependencies for every workspace
package declared in `pnpm-workspace.yaml` (`engine/`, `cli/`) in one pass,
and symlinks `@quay/cli`'s `workspace:*` dependency on `@quay/engine`
locally -- no publishing step needed during development.

## Project layout recap

- `engine/` -- `@quay/engine`. Pure JS, no UI framework. Owns framing
  (`src/frame.js`), manifest/chunking/hashing (`src/transfer.js`), and will
  own the Hyperswarm/Hyperdht join logic starting with plan item 2.
- `cli/` -- `@quay/cli`. `src/send.js` / `src/receive.js` are the two CLI
  halves from plan section 4, item 1; `src/demo-loopback.js` orchestrates
  both for a manual demo; `test/` holds the automated `node:test` suite.
- `docs/` -- the product/phasing plan, condensed architecture notes, and
  this setup guide.

## Running the CLI by hand

Two terminals, from the repo root:

```bash
# terminal 1
node cli/src/receive.js 5000 /tmp/quay-received

# terminal 2
node cli/src/send.js 5000 /path/to/some/file
```

Both processes print a `sha256:` line; they should match. Port `0` in
place of `5000` asks the OS for a free port (the demo script uses this).

## Adding a Holepunch package

Pin exact versions (per the plan's Phase A instruction) and install into
the workspace that needs it, e.g.:

```bash
pnpm add hypercore@11.36.1 --filter @quay/engine --save-exact
```

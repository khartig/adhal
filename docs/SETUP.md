# Setup

## Prerequisites

- Node.js >= 18 (developed against v22.11.0 via nvm). Check with `node -v`.
- npm (ships with Node; developed against 10.9.0).
- git, and the [GitHub CLI](https://cli.github.com/) (`gh`) if you want to
  work with pull requests/issues from the terminal.

## Getting the code running

```bash
git clone <repo-url> quay
cd quay
npm install            # installs root + engine + cli workspaces in one pass
npm test                # runs the item-1 loopback proof automatically
npm run demo:loopback   # runs it manually; prints both sides' output live
```

`npm install` at the repo root installs dependencies for every npm
workspace (`engine/`, `cli/`) in one pass, and links `@quay/cli`'s
dependency on `@quay/engine` locally -- no publishing step needed during
development.

## IntelliJ IDEA

This is a plain Node.js monorepo; there's no hand-authored `.idea/`
project file checked into git (IDE state is personal and `.idea/` is
git-ignored). To open it:

1. `File > Open...` and select the `quay/` root folder (not a subfolder).
2. If prompted, install/enable the **Node.js** plugin (Preferences ->
   Plugins -> search "Node.js").
3. Preferences -> Languages & Frameworks -> Node.js: point the Node
   interpreter at your local install (e.g. the nvm path returned by
   `which node`).
4. IntelliJ will detect `package.json` in the root, `engine/`, and `cli/`
   automatically since they're declared as npm workspaces in the root
   `package.json`.
5. Optional: right-click `cli/test/local-loopback.test.js` -> "Run" to
   execute it directly from the IDE (IntelliJ auto-detects Node's built-in
   test runner via the `node:test` import).

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
npm install hypercore@11.36.1 --workspace=engine --save-exact
```

# Setup

## Prerequisites

- Node.js >= 24, which is what CI runs. Check with `node -v`. 22.x is not
  enough: six stall-timer and size-cap tests are reported cancelled there
  rather than run (PROTOCOL.md §8.1).
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
and symlinks `@ad-hal/cli`'s `workspace:*` dependency on `@ad-hal/engine`
locally -- no publishing step needed during development.

## Project layout recap

- `engine/` -- `@ad-hal/engine`. Pure JS, no UI framework. Owns framing
  (`src/frame.js`), manifest/chunking/hashing (`src/transfer.js`), and will
  own the Hyperswarm/Hyperdht join logic.
- `cli/` -- `@ad-hal/cli`. `src/swarm-send.js` / `src/swarm-receive.js`
  are the real CLIs, published as the `ad-hal-send` / `ad-hal-receive`
  bins. `src/send.js` / `src/receive.js` are the loopback pair, over
  127.0.0.1 only: **test-only**, kept for the tests and demos, and not
  published. `src/demo-loopback.js` orchestrates both for a manual demo;
  `test/` holds the automated `node:test` suite.
- `docs/` -- the product/phasing plan, condensed architecture notes, and
  this setup guide.

## Running the CLI by hand

Two terminals, from the repo root:

```bash
# terminal 1 -- prints a drop code
node cli/src/receive.js 5000 /tmp/adhal-received

# terminal 2 -- paste the code at the prompt
node cli/src/send.js 5000 - /path/to/some/file
```

The two sides run the same CPace handshake as the swarm CLIs, over plain
TCP, and every frame after it is sealed under the keys it derives
(`docs/PROTOCOL.md` §3.3–3.4). The code can also be passed in place of
`-`, with `--code-on-argv`, at the cost of leaving it in shell history.
Terminal 1 shows the offer and asks before accepting it; `--yes` skips the
question, and without a terminal to ask on the offer is declined. Both
processes print a `sha256:` line; they should match. Port `0` in place of
`5000` asks the OS for a free port (the demo script uses this).

## TypeScript (checkJs, no build step)

Source stays plain `.js` (CommonJS, matching the Holepunch packages) --
there is no compile step and the dev/run workflow (`node cli/src/send.js`,
`node --test`) is unchanged. `tsconfig.json` at the repo root turns on
`checkJs`/`allowJs`/`noEmit` so TypeScript type-checks the existing JS
using inferred types plus JSDoc hints where inference is ambiguous (see
`engine/src/transfer.js` and `cli/src/demo-loopback.js` for examples).
Run it with:

```bash
pnpm run typecheck
```

`hyperswarm`, `hyperdht`, and `hypercore-crypto` ship no type
declarations at all (`b4a`, `@noble/curves` and `@noble/hashes` do).
`engine/src/swarm.js` imports them anyway, and they type-check as `any`,
because `tsconfig.json` leaves `noImplicitAny` off. So nothing that goes
through those packages is checked. If it ever needs to be, add a small
ambient `.d.ts` shim under a new `types/` directory (only for the
functions actually called) rather than turning off `checkJs`.

## Adding a Holepunch package

Pin exact versions, as every dependency here already is, and install into
the workspace that needs it, e.g.:

```bash
pnpm add hypercore@11.36.1 --filter @ad-hal/engine --save-exact
```

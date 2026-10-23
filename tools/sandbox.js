'use strict'

// A copy of the workspace to plant bugs in.
//
// Two things here break the code on purpose: the conformance harness's
// planted-bug test (conformance/test/planted.test.js), which shows that
// each check the harness makes can fail, and the mutation runner
// (tools/mutate.js). Neither may touch the working tree. A break planted
// in place and undone with `git checkout` also discards whatever else was
// uncommitted in that file, which has happened here once, so a break goes
// into a copy, and a file is restored from the working tree's own,
// untouched version rather than from git.
//
// THE COPY. The workspace packages are copied as they are on disk,
// uncommitted changes included, with their own node_modules: under pnpm
// those are directories of relative symlinks, so cli/node_modules/@ad-hal/
// engine in the copy points at the copy's engine/, and a mutant in the
// copy's engine/src is what the copy's tests load. The root node_modules,
// where the third-party packages live, is linked rather than copied: it is
// most of the size, and nothing here mutates it.

const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')

const REPO = path.resolve(__dirname, '..')

/**
 * @param {{ packages?: string[] }} [o] the workspace packages to copy
 */
function makeSandbox ({ packages = ['engine', 'cli', 'conformance'] } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'adhal-sandbox-'))
  for (const pkg of packages) {
    fs.cpSync(path.join(REPO, pkg), path.join(root, pkg), { recursive: true, verbatimSymlinks: true })
  }
  // The root files the suite reads: dependency-pins.test.js checks the
  // lockfile, so a copy without it fails before any mutant is planted.
  for (const file of ['package.json', 'pnpm-workspace.yaml', 'pnpm-lock.yaml']) fs.copyFileSync(path.join(REPO, file), path.join(root, file))
  fs.symlinkSync(path.join(REPO, 'node_modules'), path.join(root, 'node_modules'), 'dir')

  return {
    root,
    /** @param {string} rel a path relative to the repository root */
    path: (rel) => path.join(root, rel),
    /** @param {string} rel */
    read: (rel) => fs.readFileSync(path.join(root, rel), 'utf8'),
    /** @param {string} rel @param {string} text */
    write: (rel, text) => fs.writeFileSync(path.join(root, rel), text),
    /** Puts back the working tree's version of `rel`. @param {string} rel */
    restore: (rel) => fs.copyFileSync(path.join(REPO, rel), path.join(root, rel)),
    dispose: () => fs.rmSync(root, { recursive: true, force: true })
  }
}

module.exports = { makeSandbox, REPO }

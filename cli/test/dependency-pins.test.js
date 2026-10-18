'use strict'

// The @noble pins PROTOCOL.md section 12.4 says the security claims rest on.
//
// WHY A VERSION NUMBER IS A SECURITY PROPERTY HERE. engine/src/cpace.js
// imports the Elligator2 map as `_map_to_curve_elligator2_curve25519`, an
// export @noble/curves marks experimental: underscored, and free to be
// renamed or to change behaviour in any release. The CFRG vectors in
// cpace-vectors.test.js catch a change in what the map computes. They do
// not catch the pin itself being loosened -- "2.4.0" edited to "^2.4.0"
// passes every test on the day it lands, because the lockfile still
// resolves 2.4.0, and fails on whichever later day noble publishes. This
// file fails on the day of the edit instead.
//
// AN UPGRADE IS MEANT TO FAIL THIS TEST. PINNED below is a copy, on
// purpose, so that moving either package means editing a test that says
// what the move is: a change to the security argument, reviewed as one
// (section 12.4). Re-run cpace-vectors.test.js against the new version
// and record the upgrade in PROTOCOL.md before changing PINNED.
//
// Three layers, because each can drift without the others: what
// engine/package.json asks for, what pnpm-lock.yaml resolved, and what
// cpace.js actually loads at runtime. CI's --frozen-lockfile ties the
// first two together but says nothing about either being exact.

const test = require('node:test')
const assert = require('node:assert/strict')
const path = require('node:path')
const fs = require('node:fs')

const REPO_ROOT = path.resolve(__dirname, '..', '..')
const ENGINE = path.join(REPO_ROOT, 'engine')

const PINNED = {
  '@noble/curves': '2.4.0',
  '@noble/hashes': '2.4.0'
}

// What cpace.js imports from each package. Resolved from engine/src so the
// copy checked is the copy cpace.js gets, not whichever one cli/ sees.
const ENTRY = {
  '@noble/curves': '@noble/curves/ed25519.js',
  '@noble/hashes': '@noble/hashes/sha2.js'
}

const EXACT = /^\d+\.\d+\.\d+$/

/** @param {string} s */
const escape = (s) => s.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&')

/**
 * The installed package.json for a module, found by walking up from the
 * file a require resolves to. Neither noble package exports
 * "./package.json", so require('@noble/curves/package.json') throws.
 *
 * @param {string} entry
 * @param {string} name
 */
function installedManifest (entry, name) {
  let dir = path.dirname(require.resolve(entry, { paths: [path.join(ENGINE, 'src')] }))
  for (;;) {
    const candidate = path.join(dir, 'package.json')
    if (fs.existsSync(candidate)) {
      const manifest = JSON.parse(fs.readFileSync(candidate, 'utf8'))
      if (manifest.name === name) return manifest
    }
    const parent = path.dirname(dir)
    if (parent === dir) throw new Error(`no package.json named ${name} above ${entry}`)
    dir = parent
  }
}

test('engine/package.json pins each @noble package to an exact version', () => {
  const { dependencies } = JSON.parse(fs.readFileSync(path.join(ENGINE, 'package.json'), 'utf8'))
  for (const [name, version] of Object.entries(PINNED)) {
    assert.match(dependencies[name], EXACT, `${name} must be an exact version, not a range: "${dependencies[name]}"`)
    assert.equal(dependencies[name], version, `${name} moved; see the note on PINNED`)
  }
})

test('pnpm-lock.yaml resolves each @noble package to the pin, and to nothing else', () => {
  // A Windows checkout with core.autocrlf hands us CRLF; the patterns
  // below are about the lockfile's layout, not its line endings.
  const lock = fs.readFileSync(path.join(REPO_ROOT, 'pnpm-lock.yaml'), 'utf8').replace(/\r\n/g, '\n')

  // The engine importer's block, up to the blank line that ends it.
  const engine = lock.match(/^ {2}engine:\n {4}dependencies:\n([\s\S]*?)\n\n/m)
  assert.ok(engine, 'pnpm-lock.yaml has no engine importer; the lockfile layout changed')

  for (const [name, version] of Object.entries(PINNED)) {
    const entry = engine[1].match(new RegExp(
      `^ {6}'${escape(name)}':\\n {8}specifier: (.+)\\n {8}version: (.+)$`, 'm'
    ))
    assert.ok(entry, `the engine importer does not list ${name}`)
    assert.equal(entry[1], version, `${name}'s locked specifier`)
    assert.equal(entry[2], version, `${name}'s locked version`)

    // A second copy anywhere in the tree would mean some import path gets
    // a version nobody reviewed.
    const resolved = new Set(
      [...lock.matchAll(new RegExp(`^ {2}'${escape(name)}@([^']+)':`, 'gm'))].map((m) => m[1])
    )
    assert.deepEqual([...resolved], [version], `${name} resolves to more than the pin: ${[...resolved].join(', ')}`)
  }
})

test('the copy cpace.js loads is the pinned version', () => {
  for (const [name, version] of Object.entries(PINNED)) {
    assert.equal(installedManifest(ENTRY[name], name).version, version, `installed ${name}; run pnpm install --frozen-lockfile`)
  }
})

test('the experimental Elligator2 export cpace.js uses still exists', () => {
  // A rename would otherwise surface as "mapToCurveElligator2 is not a
  // function" from inside calculateGenerator, on the first handshake. This
  // names the cause.
  const curves = require(require.resolve('@noble/curves/ed25519.js', { paths: [path.join(ENGINE, 'src')] }))
  assert.equal(
    typeof curves._map_to_curve_elligator2_curve25519, 'function',
    '@noble/curves no longer exports _map_to_curve_elligator2_curve25519 (PROTOCOL.md section 12.4)'
  )
})

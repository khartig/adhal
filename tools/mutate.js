#!/usr/bin/env node
'use strict'

// Mutation testing for the security-critical engine modules (Q-06), with no
// dependency.
//
// A mutant is the engine with one small change -- a `<` made `<=`, a
// `throw` made a no-op, a constant moved by one -- that a test suite worth
// its name should notice. Each is planted in a copy of the workspace
// (tools/sandbox.js; the working tree is never touched) and the tests are
// run against it. A mutant the tests fail on is KILLED. One they pass is a
// SURVIVOR, and a survivor is either a gap in the tests or an equivalent
// mutant, a change no input can observe. Every survivor is triaged as one
// or the other; docs/history/WORK-RECORD.md has the triage of the W12 run.
//
// THE TESTS, IN PHASES, because the fast tier takes 12 s and there are
// hundreds of mutants:
//
//   1. the test files most likely to notice a change in this module
//   2. the rest of the fast tier, only for what survives phase 1
//   3. with --conformance, the conformance harness against the mutant
//      engine's adapter, only for what survives phase 2
//
// Every run is seeded (ADHAL_FUZZ_SEED, ADHAL_PROPERTY_SEED) so a mutant's
// result reproduces, with one exception the fuzz harness owns: its starting
// corpus for several targets comes from crypto.randomBytes, outside the
// seed. A mutant killed only by the fuzz harness can, rarely, survive a
// second run.
//
//   node tools/mutate.js [--files engine/src/channel.js,...] [--workers 4]
//                        [--sample N] [--seed hex] [--conformance] [--report path]

const fs = require('node:fs')
const os = require('node:os')
const path = require('node:path')
const crypto = require('node:crypto')
const { spawn, spawnSync } = require('node:child_process')

const { makeSandbox, REPO } = require('./sandbox')

// Each module, and the test files that exercise it most directly.
const TARGETS = {
  'engine/src/channel.js': ['channel', 'frame', 'sealed-transfer', 'property', 'fuzz'],
  'engine/src/frame.js': ['frame', 'channel', 'property', 'fuzz'],
  'engine/src/reader.js': ['pake-handshake', 'fuzz'],
  'engine/src/cpace.js': ['cpace-vectors', 'handshake-vectors', 'pake-handshake'],
  'engine/src/handshake.js': ['handshake-vectors', 'pake-handshake', 'attempts', 'property', 'fuzz'],
  'engine/src/attempts.js': ['attempts', 'pake-handshake'],
  'engine/src/message.js': ['result', 'manifest', 'stream', 'accept-gate', 'property', 'fuzz'],
  'engine/src/names.js': ['manifest', 'hardening', 'property', 'fuzz'],
  'engine/src/transfer.js': ['accept-gate', 'resume', 'stream', 'result', 'hardening', 'sealed-transfer', 'cancel', 'manifest', 'property', 'state-machine']
}

const SEEDS = { ADHAL_FUZZ_SEED: '5eed0001', ADHAL_PROPERTY_SEED: '5eed0002' }
// A mutant that makes something loop or wait forever is killed by the
// timeout rather than waited on: no test file takes 15 s unmutated, and the
// longest phase about 20 s.
const PHASE_TIMEOUT_MS = 45000
const TEST_TIMEOUT_MS = 15000

// --- finding the places to mutate ----------------------------------------

/**
 * The offsets of `source` that are code: not inside a comment, a string,
 * a template literal, or a regular expression. A character-level scan,
 * which is enough because a mutant it misjudges either fails `node
 * --check` and is dropped, or is a mutant like any other.
 * @param {string} source
 * @returns {Uint8Array} 1 where the character is code
 */
function codeMask (source) {
  const mask = new Uint8Array(source.length)
  let i = 0
  let prev = '' // the last significant code character, for telling a regex from a division
  const regexCanFollow = (/** @type {string} */ p) => p === '' || '(,=:[!&|?{};+-*%<>~^'.includes(p)
  while (i < source.length) {
    const c = source[i]
    const d = source[i + 1]
    if (c === '/' && d === '/') { while (i < source.length && source[i] !== '\n') i++; continue }
    if (c === '/' && d === '*') { const end = source.indexOf('*/', i + 2); i = end === -1 ? source.length : end + 2; continue }
    if (c === '\'' || c === '"' || c === '`') {
      i++
      while (i < source.length && source[i] !== c) { if (source[i] === '\\') i++; i++ }
      i++
      prev = 'x'
      continue
    }
    if (c === '/' && regexCanFollow(prev)) {
      i++
      let inClass = false
      while (i < source.length && (inClass || source[i] !== '/') && source[i] !== '\n') {
        if (source[i] === '\\') i++
        else if (source[i] === '[') inClass = true
        else if (source[i] === ']') inClass = false
        i++
      }
      i++
      while (/[a-z]/.test(source[i] || '')) i++
      prev = 'x'
      continue
    }
    mask[i] = 1
    if (!/\s/.test(c)) prev = c
    i++
  }
  return mask
}

// The operators, as [pattern, replacement, name]. A pattern matches at a
// code offset; `guard` rejects matches that are part of a longer token.
const OPERATORS = [
  { name: '=== to !==', find: '===', to: '!==' },
  { name: '!== to ===', find: '!==', to: '===' },
  { name: '<= to <', find: '<=', to: '<' },
  { name: '>= to >', find: '>=', to: '>' },
  { name: '< to <=', find: '<', to: '<=', guard: (/** @type {string} */ s, /** @type {number} */ i) => s[i + 1] !== '=' && s[i + 1] !== '<' && s[i - 1] !== '<' },
  { name: '> to >=', find: '>', to: '>=', guard: (/** @type {string} */ s, /** @type {number} */ i) => s[i + 1] !== '=' && s[i + 1] !== '>' && s[i - 1] !== '>' && s[i - 1] !== '=' },
  { name: '&& to ||', find: '&&', to: '||' },
  { name: '|| to &&', find: '||', to: '&&' },
  { name: '+ to -', find: '+', to: '-', guard: (/** @type {string} */ s, /** @type {number} */ i) => s[i + 1] !== '+' && s[i + 1] !== '=' && s[i - 1] !== '+' && /[\w)\]] *$/.test(s.slice(Math.max(0, i - 3), i)) },
  { name: '- to +', find: '-', to: '+', guard: (/** @type {string} */ s, /** @type {number} */ i) => s[i + 1] !== '-' && s[i + 1] !== '=' && s[i - 1] !== '-' && /[\w)\]] *$/.test(s.slice(Math.max(0, i - 3), i)) },
  { name: 'true to false', find: 'true', to: 'false', word: true },
  { name: 'false to true', find: 'false', to: 'true', word: true },
  { name: 'throw removed', find: 'throw ', to: 'void ', word: true },
  { name: '! removed', find: '!', to: '', guard: (/** @type {string} */ s, /** @type {number} */ i) => s[i + 1] !== '=' }
]

/**
 * Every mutant of one file, as { file, offset, length, to, operator, line }.
 * @param {string} file @param {string} source
 */
function mutantsOf (file, source) {
  const mask = codeMask(source)
  const lines = source.slice(0, source.length).split('\n')
  const lineAt = (/** @type {number} */ offset) => source.slice(0, offset).split('\n').length
  /** @type {any[]} */
  const out = []
  // Nothing at module level outside function bodies other than constants
  // and requires; requires are not worth mutating.
  const skipLine = (/** @type {number} */ n) => /require\(|^module\.exports|^\s*'use strict'/.test(lines[n - 1])
  for (const op of OPERATORS) {
    let i = source.indexOf(op.find)
    while (i !== -1) {
      const inCode = [...op.find].every((_, k) => mask[i + k])
      const wordOk = !op.word || (!/[\w$]/.test(source[i - 1] || '') && !/[\w$]/.test(source[i + op.find.trimEnd().length] || ''))
      if (inCode && wordOk && (!op.guard || op.guard(source, i)) && !skipLine(lineAt(i))) {
        out.push({ file, offset: i, length: op.find.length, to: op.to, operator: op.name, line: lineAt(i) })
      }
      i = source.indexOf(op.find, i + 1)
    }
  }
  // Integer literals moved by one.
  const number = /\b\d+\b/g
  for (let m = number.exec(source); m; m = number.exec(source)) {
    const at = m.index
    if (!mask[at] || /[\w$.]/.test(source[at - 1] || '') || /[.xXnbBoOeE_]/.test(source[at + m[0].length] || '')) continue
    if (skipLine(lineAt(at))) continue
    out.push({ file, offset: at, length: m[0].length, to: String(Number(m[0]) + 1), operator: 'integer + 1', line: lineAt(at) })
  }
  return out.sort((a, b) => a.offset - b.offset)
}

// --- running one mutant ---------------------------------------------------

/**
 * @param {string} cwd @param {string[]} args @param {Record<string, string>} env
 * @returns {Promise<'pass' | 'fail' | 'timeout'>}
 */
function run (cwd, args, env) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, args, { cwd, env: { ...process.env, ...SEEDS, ...env }, stdio: 'ignore', detached: true })
    const timer = setTimeout(() => {
      try { process.kill(-(/** @type {number} */ (child.pid)), 'SIGKILL') } catch {}
      resolve('timeout')
    }, PHASE_TIMEOUT_MS)
    child.on('exit', (code) => {
      clearTimeout(timer)
      resolve(code === 0 ? 'pass' : 'fail')
    })
  })
}

/**
 * @param {ReturnType<typeof makeSandbox>} box @param {any} mutant
 * @param {{ conformance: boolean, allTests: string[] }} o
 */
async function evaluate (box, mutant, { conformance, allTests }) {
  const original = box.read(mutant.file)
  const mutated = original.slice(0, mutant.offset) + mutant.to + original.slice(mutant.offset + mutant.length)
  box.write(mutant.file, mutated)
  const started = Date.now()
  try {
    if (spawnSync(process.execPath, ['--check', box.path(mutant.file)]).status !== 0) return { status: 'invalid', ms: 0 }
    const cli = box.path('cli')
    const first = TARGETS[/** @type {keyof typeof TARGETS} */ (mutant.file)].map((t) => `test/${t}.test.js`)
    const r1 = await run(cli, ['--test', '--test-concurrency=4', `--test-timeout=${TEST_TIMEOUT_MS}`, ...first], { ADHAL_FAST: '1' })
    if (r1 !== 'pass') return { status: 'killed', by: `phase 1 (${r1})`, ms: Date.now() - started }
    const rest = allTests.filter((t) => !first.includes(t))
    const phase2 = () => run(cli, ['--test', '--test-concurrency=4', `--test-timeout=${TEST_TIMEOUT_MS}`, ...rest], { ADHAL_FAST: '1' })
    // CONFIRMED, because phase 2 is where a flaky test would do harm: it
    // runs only for what phase 1 missed, so a spurious failure there
    // kills exactly the mutants worth looking at. Two tests in the fast
    // tier fail about 1 run in 15 under this runner's load (both timing
    // races in the tests; docs/history/WORK-RECORD.md, W12). A mutant the
    // tests really catch fails twice; a flake almost never does.
    let r2 = await phase2()
    if (r2 !== 'pass') {
      const again = await phase2()
      if (again === 'pass') r2 = 'pass'
    }
    if (r2 !== 'pass') return { status: 'killed', by: `phase 2 (${r2}, confirmed)`, ms: Date.now() - started }
    if (conformance) {
      const r3 = await run(box.root, [path.join('conformance', 'src', 'cli.js'), '--', process.execPath, path.join('conformance', 'adapters', 'engine.js')], {})
      if (r3 !== 'pass') return { status: 'killed', by: `conformance (${r3})`, ms: Date.now() - started }
    }
    return { status: 'survived', ms: Date.now() - started }
  } finally {
    box.restore(mutant.file)
  }
}

// --- the run --------------------------------------------------------------

/** @param {string[]} argv */
function options (argv) {
  /** @param {string} name */
  const value = (name) => { const i = argv.indexOf(name); return i === -1 ? undefined : argv[i + 1] }
  return {
    files: (value('--files') || Object.keys(TARGETS).join(',')).split(','),
    workers: Number(value('--workers') || Math.max(1, Math.floor(os.availableParallelism() / 3))),
    sample: value('--sample') ? Number(value('--sample')) : null,
    seed: value('--seed') || '6d757461',
    conformance: argv.includes('--conformance'),
    report: value('--report') || null,
    list: argv.includes('--list')
  }
}

async function main () {
  const o = options(process.argv.slice(2))
  for (const f of o.files) if (!(f in TARGETS)) throw new Error(`not a mutation target: ${f}; the targets are ${Object.keys(TARGETS).join(', ')}`)

  let mutants = o.files.flatMap((f) => mutantsOf(f, fs.readFileSync(path.join(REPO, f), 'utf8')))
  const total = mutants.length
  if (o.sample !== null && o.sample < mutants.length) {
    // A seeded sample, so a sampled run can be repeated exactly.
    const key = (/** @type {any} */ m) => crypto.createHash('sha256').update(`${o.seed}:${m.file}:${m.offset}:${m.operator}`).digest('hex')
    mutants = mutants.map((m) => ({ m, k: key(m) })).sort((a, b) => a.k.localeCompare(b.k)).slice(0, o.sample).map((x) => x.m)
      .sort((a, b) => a.file.localeCompare(b.file) || a.offset - b.offset)
  }
  if (o.list) {
    for (const m of mutants) console.log(`${m.file}:${m.line}  ${m.operator}`)
    console.log(`${mutants.length} of ${total} mutants`)
    return
  }

  const allTests = fs.readdirSync(path.join(REPO, 'cli', 'test')).filter((f) => f.endsWith('.test.js')).map((f) => `test/${f}`)
  const boxes = Array.from({ length: Math.min(o.workers, mutants.length) }, () => makeSandbox())
  const lines = Object.fromEntries(o.files.map((f) => [f, fs.readFileSync(path.join(REPO, f), 'utf8').split('\n')]))
  /** @type {any[]} */
  const results = []
  let next = 0
  const started = Date.now()
  process.stderr.write(`${mutants.length} mutants (of ${total}) across ${o.files.length} files, ${boxes.length} workers\n`)
  try {
    // The baseline: the unmutated copy, under the same phases, timeouts,
    // and concurrency. A suite that fails here would count every mutant
    // as killed.
    for (const f of o.files) {
      const b = await evaluate(boxes[0], { file: f, offset: 0, length: 0, to: '' }, { conformance: o.conformance, allTests })
      if (b.status !== 'survived') throw new Error(`the unmutated copy fails for ${f} (${b.by}); no mutant result would mean anything`)
    }
    process.stderr.write(`baseline passes, ${Math.round((Date.now() - started) / 1000)}s\n`)
    await Promise.all(boxes.map(async (box) => {
      while (next < mutants.length) {
        const m = mutants[next++]
        const r = await evaluate(box, m, { conformance: o.conformance, allTests })
        const result = { ...m, ...r, source: lines[m.file][m.line - 1].trim() }
        results.push(result)
        if (r.status === 'survived') process.stderr.write(`SURVIVED ${m.file}:${m.line} ${m.operator}: ${result.source}\n`)
        if (results.length % 25 === 0) process.stderr.write(`${results.length}/${mutants.length} after ${Math.round((Date.now() - started) / 1000)}s\n`)
      }
    }))
  } finally {
    for (const box of boxes) box.dispose()
  }

  results.sort((a, b) => a.file.localeCompare(b.file) || a.offset - b.offset)
  /** @type {Record<string, { killed: number, survived: number, invalid: number }>} */
  const byFile = {}
  for (const r of results) {
    const s = byFile[r.file] || (byFile[r.file] = { killed: 0, survived: 0, invalid: 0 })
    s[/** @type {'killed' | 'survived' | 'invalid'} */ (r.status)]++
  }
  console.log('file                          killed  survived  invalid  score')
  for (const [file, s] of Object.entries(byFile)) {
    const score = s.killed + s.survived ? (100 * s.killed / (s.killed + s.survived)).toFixed(1) : '-'
    console.log(`${file.padEnd(30)}${String(s.killed).padStart(6)}${String(s.survived).padStart(10)}${String(s.invalid).padStart(9)}  ${score}%`)
  }
  const survivors = results.filter((r) => r.status === 'survived')
  console.log(`\n${survivors.length} survivors, ${Math.round((Date.now() - started) / 1000)}s`)
  for (const r of survivors) console.log(`  ${r.file}:${r.line}  ${r.operator}  ${r.source}`)
  if (o.report) fs.writeFileSync(o.report, JSON.stringify({ seeds: SEEDS, sample: o.sample, seed: o.seed, total, results }, null, 2) + '\n')
}

main().catch((err) => {
  console.error(err && err.stack ? err.stack : err)
  process.exitCode = 2
})

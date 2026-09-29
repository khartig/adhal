'use strict'

// W15c: a code on the command line is refused unless --code-on-argv says
// the leak is accepted (Q-17), and every CLI says in --help what it does
// not protect (Q-09, Q-13).

const test = require('node:test')
const assert = require('node:assert/strict')
const path = require('node:path')
const os = require('node:os')
const fs = require('node:fs')
const { spawn } = require('node:child_process')

const { generateCode } = require('@ad-hal/engine')
const { readCode } = require('../src/read-code')
const { slow } = require('../test-helpers/tiers')

const SRC = path.join(__dirname, '..', 'src')

test('a code on argv is refused without --code-on-argv, and the refusal does not repeat it', async () => {
  const code = generateCode()
  /** @type {string[]} */
  const warned = []
  await assert.rejects(
    readCode({ argvCode: code, label: 'x', warn: (l) => warned.push(l) }),
    (err) => {
      const message = /** @type {Error} */ (err).message
      assert.match(message, /shell history/)
      assert.match(message, /Pass `-` instead/)
      assert.match(message, /--code-on-argv/)
      assert.ok(!message.includes(code), 'the code itself is not echoed')
      return true
    }
  )
  assert.deepEqual(warned, [])
})

test('with --code-on-argv the code is taken, and the leak is still named', async () => {
  const code = generateCode()
  /** @type {string[]} */
  const warned = []
  assert.equal(await readCode({ argvCode: code, label: 'x', allowArgv: true, warn: (l) => warned.push(l) }), code)
  assert.equal(warned.length, 1)
  assert.match(warned[0], /shell history and visible to `ps`/)
})

/**
 * @param {string} script
 * @param {string[]} args
 * @returns {Promise<{ code: number | null, stdout: string, stderr: string }>}
 */
function run (script, args) {
  return new Promise((resolve) => {
    // No bootstrap: every case here must end before any network work.
    const child = spawn(process.execPath, [path.join(SRC, script), ...args], {
      env: { ...process.env, NO_COLOR: '1', ADHAL_NO_PROGRESS: '1', ADHAL_BOOTSTRAP: '[{"host":"127.0.0.1","port":9}]', ADHAL_JOIN_TIMEOUT: '1' }
    })
    child.stdin.end()
    let stdout = ''
    let stderr = ''
    child.stdout.on('data', (c) => { stdout += c })
    child.stderr.on('data', (c) => { stderr += c })
    child.on('close', (code) => resolve({ code, stdout, stderr }))
  })
}

test('every CLI that takes a code refuses one on argv, before any network work', slow, async (t) => {
  const dir = await fs.promises.mkdtemp(path.join(os.tmpdir(), 'adhal-argv-'))
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }))
  const file = path.join(dir, 'f.txt')
  await fs.promises.writeFile(file, 'x')
  const code = generateCode()

  /** @type {Array<[string, string[]]>} */
  const cases = [
    ['swarm-send.js', [code, file]],
    ['swarm-receive.js', [code, dir]],
    ['send.js', ['9', code, file]]
  ]
  for (const [script, args] of cases) {
    const out = await run(script, args)
    assert.equal(out.code, 1, `${script}: ${out.stdout}${out.stderr}`)
    assert.match(out.stderr, /refusing a code given on the command line/, script)
    assert.doesNotMatch(out.stdout, /joining topic|connected/, `${script} must stop before the network`)
    assert.ok(!(out.stdout + out.stderr).includes(code), `${script} must not print the code back`)
  }
})

test('--help says what each CLI does not protect', slow, async () => {
  for (const script of ['swarm-send.js', 'swarm-receive.js']) {
    const out = await run(script, ['--help'])
    assert.equal(out.code, 0)
    assert.match(out.stdout, /not anonymous: your IP address is visible to the peer/, script)
    assert.match(out.stdout, /--code-on-argv/, script)
  }
  const rx = await run('swarm-receive.js', ['--help'])
  assert.match(rx.stdout, /--yes/)
  assert.match(rx.stdout, /With no terminal to ask on and no --yes, the\s+offer is declined/)

  for (const script of ['send.js', 'receive.js']) {
    const out = await run(script, ['--help'])
    assert.equal(out.code, 0)
    assert.match(out.stdout, /TEST-ONLY/, script)
  }
})

test('the published bins are the swarm CLIs, not the loopback harness', () => {
  // Q-13: `ad-hal-send` used to be the 127.0.0.1-only send.js.
  const { bin } = require('../package.json')
  assert.deepEqual(bin, {
    'ad-hal-send': 'src/swarm-send.js',
    'ad-hal-receive': 'src/swarm-receive.js',
    'ad-hal-code': 'src/code.js'
  })
})

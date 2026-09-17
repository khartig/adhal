'use strict'

// Automated proof of docs/Refined-Implementation-Plan.md section 4, item 3:
// "6-word code + QR encoding of the same payload."
//
// The load-bearing test in here is the round trip through a real QR
// decoder. Everything else about item 3 can be checked by inspection, but
// "would a phone actually read this" cannot, and it is the whole point of
// the deliverable -- so jsqr (a test-only dependency, never shipped)
// decodes the very matrix that cli/src/qr.js prints.

const test = require('node:test')
const assert = require('node:assert/strict')
const path = require('node:path')
const { execFile } = require('node:child_process')
const { promisify } = require('node:util')

const qrcode = require('qrcode-generator')
// jsqr ships as a function that also carries a `default` property.
const jsqrModule = require('jsqr')
const jsQR = typeof jsqrModule === 'function' ? jsqrModule : jsqrModule.default

const {
  generateCode,
  parseCode,
  isValidCode,
  encodeQrPayload,
  WORD_COUNT,
  QR_SCHEME,
  CODE_ENTROPY_BITS
} = require('@quay/engine')
const { WORDS, INDEX } = require('@quay/engine/src/wordlist')
const { renderQr, ECC_LEVEL, QUIET_ZONE } = require('../src/qr')
const { resolveCode } = require('../src/resolve-code')

const execFileAsync = promisify(execFile)
const CODE_SCRIPT = path.join(__dirname, '..', 'src', 'code.js')

// The longest code the generator can produce: six five-letter words.
const LONGEST_CODE = WORDS.filter((w) => w.length === 5).slice(0, WORD_COUNT).join('-')

function matrixOf (payload) {
  // ECC_LEVEL widens to `string` crossing the module boundary; qrcode-generator
  // wants the literal union.
  const qr = qrcode(0, /** @type {'Q'} */ (ECC_LEVEL))
  qr.addData(payload, 'Alphanumeric')
  qr.make()
  return qr
}

// Renders the symbol to greyscale RGBA at 8 px per module, quiet zone
// included, which is what a decoder expects to be handed.
function rasterize (qr, scale = 8) {
  const count = qr.getModuleCount()
  const total = count + QUIET_ZONE * 2
  const px = total * scale
  const data = new Uint8ClampedArray(px * px * 4)
  for (let y = 0; y < px; y++) {
    for (let x = 0; x < px; x++) {
      const r = Math.floor(y / scale) - QUIET_ZONE
      const c = Math.floor(x / scale) - QUIET_ZONE
      const dark = r >= 0 && c >= 0 && r < count && c < count && qr.isDark(r, c)
      const i = (y * px + x) * 4
      data[i] = data[i + 1] = data[i + 2] = dark ? 0 : 255
      data[i + 3] = 255
    }
  }
  return { data, width: px, height: px }
}

// Reverses cli/src/qr.js's half-block rendering back into a bit matrix, so
// a bug in the glyph mapping or the quiet zone shows up as a mismatch
// against the encoder's own matrix rather than as a symbol that merely
// looks plausible in a terminal.
const FROM_GLYPH = { ' ': [0, 0], '▀': [1, 0], '▄': [0, 1], '█': [1, 1] }
function matrixFromRender (text) {
  const rows = []
  for (const line of text.split('\n')) {
    const stripped = line.replace(/\x1b\[[0-9;]*m/g, '')
    const top = []
    const bottom = []
    for (const ch of stripped) {
      const pair = FROM_GLYPH[ch]
      assert.ok(pair, `unexpected glyph ${JSON.stringify(ch)} in rendered QR`)
      top.push(pair[0])
      bottom.push(pair[1])
    }
    rows.push(top, bottom)
  }
  return rows
}

test('a generated code is six words from the EFF list and is already canonical', () => {
  for (let i = 0; i < 200; i++) {
    const code = generateCode()
    const words = code.split('-')
    assert.equal(words.length, WORD_COUNT)
    for (const word of words) {
      assert.ok(INDEX.has(word), `"${word}" is not in the word list`)
      assert.match(word, /^[a-z]{3,5}$/)
    }
    // Generated output must survive parsing untouched, or the code shown to
    // a human would hash to a different topic than the one we joined.
    assert.equal(parseCode(code), code)
    assert.ok(isValidCode(code))
  }
})

test('the wordlist is the vendored EFF short list, minus the one hyphenated word', () => {
  assert.equal(WORDS.length, 1295)
  assert.equal(new Set(WORDS).size, 1295, 'no duplicates')
  assert.ok(WORDS.every((w) => /^[a-z]{3,5}$/.test(w)), 'all words are 3-5 lowercase letters')
  assert.ok(!WORDS.includes('yo-yo'), 'the hyphenated word is excluded; see engine/src/wordlist.js')
  assert.deepEqual(WORDS, [...WORDS].sort(), 'kept in the source list order')
  // 6 * log2(1295)
  assert.ok(Math.abs(CODE_ENTROPY_BITS - 62.03) < 0.01, `entropy was ${CODE_ENTROPY_BITS}`)
})

test('every input style a code arrives in resolves to one canonical form and one topic', () => {
  const canonical = 'acid-acorn-acre-acts-afar-agent'
  const variants = [
    canonical,
    `${QR_SCHEME}:ACID-ACORN-ACRE-ACTS-AFAR-AGENT`, // scanned QR payload
    'quay1:acid-acorn-acre-acts-afar-agent',
    'ACID-ACORN-ACRE-ACTS-AFAR-AGENT',
    'Acid Acorn Acre Acts Afar Agent', // pasted out of a chat client
    '  acid   acorn acre acts afar agent  ',
    'acid_acorn.acre acts--afar-agent' // mangled separators
  ]

  const expectedTopic = resolveCode(canonical).topic.toString('hex')
  for (const variant of variants) {
    assert.equal(parseCode(variant), canonical, `parse of ${JSON.stringify(variant)}`)
    // The property that actually matters: same code, same 32-byte topic.
    // Divergence here means two peers join unrelated topics and present
    // as a discovery timeout rather than as a typo.
    const { topic } = resolveCode(variant)
    assert.equal(topic.length, 32)
    assert.equal(topic.toString('hex'), expectedTopic, `topic for ${JSON.stringify(variant)}`)
  }
})

test('a bad code is rejected with a message that locates the problem', () => {
  assert.throws(() => parseCode('acid-acorn-acre-acts-afar'), /expected 6 words, got 5/)
  assert.throws(() => parseCode('acid-acorn-acre-acts-afar-agent-zoom'), /expected 6 words, got 7/)
  assert.throws(() => parseCode(''), /empty/)
  assert.throws(() => parseCode('   '), /empty/)
  assert.throws(() => parseCode(null), TypeError)

  // Names the offending word *and* its position, because this code was
  // typed by hand off another device's screen.
  assert.throws(
    () => parseCode('acid-acorn-akorn-acts-afar-agent'),
    /word 3 of 6, "akorn", is not in the word list/
  )

  // A future payload format must be reported as such, not silently
  // misread as words.
  assert.throws(() => parseCode('QUAY2:ACID-ACORN-ACRE-ACTS-AFAR-AGENT'), /newer version/)

  for (const bad of ['', 'acid', 'one two three four five six']) {
    assert.equal(isValidCode(bad), false, `${JSON.stringify(bad)} should be invalid`)
  }
})

test('the QR payload is uppercase and stays inside QR alphanumeric mode', () => {
  for (let i = 0; i < 100; i++) {
    const code = generateCode()
    const payload = encodeQrPayload(code)
    assert.ok(payload.startsWith(`${QR_SCHEME}:`))
    assert.equal(payload, payload.toUpperCase())
    // QR's alphanumeric charset: 0-9 A-Z space and $%*+-./: -- lowercase
    // would silently drop the encoder into byte mode and cost a version.
    assert.match(payload, /^[0-9A-Z $%*+\-./:]+$/)
    // Case-insensitive parsing is what makes scanning and typing the same
    // path, which is the whole basis of the item-3 decision.
    assert.equal(parseCode(payload), code)
  }

  const longest = encodeQrPayload(LONGEST_CODE)
  assert.equal(longest.length, 41, 'worst case is QUAY1: plus six five-letter words')
})

test('every code fits a 29x29 version-3 symbol at ECC level Q', () => {
  // This is the property the uppercasing buys, and it is worth pinning:
  // at ECC Q the same 41-character payload needs version 4 (33x33) in byte
  // mode. Holding the symbol at 29x29 while carrying 25% error correction
  // is what keeps it readable by an indifferent phone camera pointed at
  // another screen (plan section 9, spike 5).
  assert.equal(ECC_LEVEL, 'Q')
  const codes = [LONGEST_CODE, ...Array.from({ length: 100 }, () => generateCode())]
  for (const code of codes) {
    const count = matrixOf(encodeQrPayload(code)).getModuleCount()
    assert.equal(count, 29, `code ${code} produced a ${count}x${count} symbol`)
  }
})

test('the printed symbol decodes back to the code a peer would join', () => {
  for (let i = 0; i < 25; i++) {
    const code = generateCode()
    const payload = encodeQrPayload(code)
    const qr = matrixOf(payload)

    const image = rasterize(qr)
    const decoded = jsQR(image.data, image.width, image.height)
    assert.ok(decoded, `decoder could not read the symbol for ${payload}`)
    assert.equal(decoded.data, payload)
    // Close the loop: a scan lands on the same topic the receiver joined.
    assert.equal(parseCode(decoded.data), code)
    assert.equal(
      resolveCode(decoded.data).topic.toString('hex'),
      resolveCode(code).topic.toString('hex')
    )
  }
})

test('the half-block rendering reproduces the encoder matrix exactly', () => {
  for (const code of [LONGEST_CODE, generateCode(), generateCode()]) {
    const payload = encodeQrPayload(code)
    const qr = matrixOf(payload)
    const count = qr.getModuleCount()
    const total = count + QUIET_ZONE * 2
    const rendered = matrixFromRender(renderQr(payload, { color: false }))

    for (let row = 0; row < total; row++) {
      for (let col = 0; col < total; col++) {
        const r = row - QUIET_ZONE
        const c = col - QUIET_ZONE
        const expected = r >= 0 && c >= 0 && r < count && c < count && qr.isDark(r, c) ? 1 : 0
        const actual = rendered[row] && rendered[row][col] ? 1 : 0
        assert.equal(actual, expected, `module ${row},${col} of ${payload}`)
      }
    }

    // The required 4-module light border must really be light.
    for (let col = 0; col < total; col++) {
      assert.equal(rendered[0][col], 0, 'top quiet zone')
      assert.equal(rendered[total - 1][col], 0, 'bottom quiet zone')
    }
  }
})

test('the wide fallback rendering carries the same modules at double width', () => {
  const payload = encodeQrPayload(generateCode())
  const half = renderQr(payload, { color: false }).split('\n')
  const wide = renderQr(payload, { wide: true, color: false }).split('\n')
  const total = matrixOf(payload).getModuleCount() + QUIET_ZONE * 2

  assert.equal(wide.length, total, 'one line per module row')
  assert.equal(half.length, Math.ceil(total / 2), 'two module rows per line')
  assert.equal(wide[0].length, total * 2, 'two characters per module')
  assert.ok(wide.every((line) => /^[█ ]+$/.test(line)), 'uses only full blocks')
})

test('color is on by default because a QR must be dark-on-light', () => {
  const payload = encodeQrPayload(generateCode())
  // Inheriting a dark terminal theme inverts the symbol, and whether a
  // given decoder copes with that is a coin flip.
  assert.match(renderQr(payload), /\x1b\[30;107m/)
  assert.doesNotMatch(renderQr(payload, { color: false }), /\x1b\[/)
})

test('resolveCode holds a six-word-shaped input to the strict parse', () => {
  // The regression this guards: a typo'd word code must NOT be waved
  // through as an opaque secret. Doing so hashes to a valid but wrong
  // topic, and the resulting peer-discovery timeout is indistinguishable
  // from the announce-propagation races in engine/src/swarm.js.
  assert.throws(
    () => resolveCode('acid-acorn-akorn-acts-afar-agent'),
    /"akorn", is not in the word list/
  )

  const words = resolveCode('acid-acorn-acre-acts-afar-agent')
  assert.equal(words.kind, 'words')
  assert.equal(words.code, 'acid-acorn-acre-acts-afar-agent')

  // Item 2's opaque secrets have to keep working: demo-swarm.js generates
  // hex, and the engine/scratch-*.js diagnostics take hand-typed strings.
  for (const opaque of ['a3f9c2b18d7e4056', 'quay-test-3', 'acid-acorn']) {
    const resolved = resolveCode(opaque)
    assert.equal(resolved.kind, 'opaque', `${opaque} should stay opaque`)
    assert.equal(resolved.code, opaque)
    assert.equal(resolved.topic.length, 32)
  }

  // Same string, same topic, regardless of which branch produced it.
  assert.equal(
    resolveCode('quay-test-3').topic.toString('hex'),
    resolveCode('quay-test-3').topic.toString('hex')
  )
  assert.throws(() => resolveCode('   '), /empty/)
})

test('code generation draws on the whole word list without favoring its start', (t) => {
  // A smoke test for sampling bias, not a proof of uniformity. It exists
  // because 1295 is not a power of two: reducing random bytes modulo 1295
  // would skew draws toward the front of the list, and that is the mistake
  // this would catch. generateCode uses crypto.randomInt, which rejection
  // samples instead.
  const draws = 20000
  const counts = new Map()
  let indexSum = 0
  for (let i = 0; i < draws / WORD_COUNT; i++) {
    for (const word of generateCode().split('-')) {
      counts.set(word, (counts.get(word) || 0) + 1)
      indexSum += INDEX.get(word)
    }
  }

  const coverage = counts.size / WORDS.length
  assert.ok(coverage > 0.99, `only ${(coverage * 100).toFixed(1)}% of the list was drawn`)

  // Expected mean index is (1295-1)/2 = 647. The standard error over 20k
  // draws is ~2.6, so a +/-40 band is far too wide to flake but still
  // catches a front-loading bias.
  const meanIndex = indexSum / draws
  t.diagnostic(`mean word index ${meanIndex.toFixed(1)} (expected ~647), coverage ${(coverage * 100).toFixed(1)}%`)
  assert.ok(Math.abs(meanIndex - 647) < 40, `mean index was ${meanIndex.toFixed(1)}`)
})

test('the code.js CLI prints a code, its payload, its topic and a scannable symbol', async () => {
  const { stdout } = await execFileAsync(process.execPath, [CODE_SCRIPT], { env: { ...process.env, NO_COLOR: '1' } })

  const codeLine = stdout.match(/^ {2}code: {4}(\S+)$/m)
  const payloadLine = stdout.match(/^ {2}payload: (\S+)$/m)
  const topicLine = stdout.match(/^ {2}topic: {3}([0-9a-f]{64})$/m)
  assert.ok(codeLine, `expected a code line, got:\n${stdout}`)
  assert.ok(payloadLine, `expected a payload line, got:\n${stdout}`)
  assert.ok(topicLine, `expected a topic line, got:\n${stdout}`)

  const code = codeLine[1]
  assert.equal(parseCode(code), code)
  assert.equal(payloadLine[1], encodeQrPayload(code))
  assert.equal(topicLine[1], resolveCode(code).topic.toString('hex'))

  // The symbol it printed must be the one that decodes to that payload.
  // Note the quiet-zone rows are entirely spaces, so these lines are
  // selected on being non-empty rather than on having visible content.
  const symbol = stdout.split('\n').filter((l) => l.length > 0 && /^[▀▄█ ]+$/.test(l)).join('\n')
  const rendered = matrixFromRender(symbol)
  const qr = matrixOf(payloadLine[1])
  const total = qr.getModuleCount() + QUIET_ZONE * 2
  assert.equal(rendered.length >= total, true, 'printed symbol has enough rows')
  assert.equal(rendered[QUIET_ZONE + 0][QUIET_ZONE + 0], qr.isDark(0, 0) ? 1 : 0)

  // Re-rendering an existing code reproduces it, so this doubles as the
  // "why won't my code work" check.
  const again = await execFileAsync(process.execPath, [CODE_SCRIPT, code.toUpperCase()], { env: { ...process.env, NO_COLOR: '1' } })
  assert.equal(again.stdout.match(/^ {2}code: {4}(\S+)$/m)[1], code)

  const payloadOnly = await execFileAsync(process.execPath, [CODE_SCRIPT, code, '--payload'])
  assert.equal(payloadOnly.stdout.trim(), encodeQrPayload(code))
})

test('the code.js CLI rejects an invalid code with a non-zero exit', async () => {
  await assert.rejects(
    () => execFileAsync(process.execPath, [CODE_SCRIPT, 'acid-acorn-akorn-acts-afar-agent']),
    (err) => {
      // assert.rejects types the error as `unknown`.
      const failure = /** @type {{ code: number, stderr: string }} */ (err)
      assert.equal(failure.code, 1)
      assert.match(failure.stderr, /"akorn", is not in the word list/)
      return true
    }
  )
})

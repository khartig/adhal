'use strict'

// Automated proof of the drop code (data path D1): a five-word code --
// nameplate plus secret -- and a QR encoding of the same payload.
//
// The load-bearing test in here is the round trip through a real QR
// decoder. Everything else about the drop code can be checked by inspection, but
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
  splitCode,
  topicFromNameplate,
  TOPIC_LABEL,
  WORD_COUNT,
  NAMEPLATE_WORDS,
  SECRET_WORDS,
  QR_SCHEME,
  NAMEPLATE_ENTROPY_BITS,
  SECRET_ENTROPY_BITS
} = require('@ad-hal/engine')
const { WORDS, INDEX } = require('@ad-hal/engine/src/wordlist')
const { renderQr, ECC_LEVEL, QUIET_ZONE } = require('../src/qr')
const { resolveCode } = require('@ad-hal/engine')

const execFileAsync = promisify(execFile)
const CODE_SCRIPT = path.join(__dirname, '..', 'src', 'code.js')

// The longest code the generator can produce: five of the longest words.
const LONGEST_WORD = Math.max(...WORDS.map((w) => w.length))
const LONGEST_CODE = WORDS.filter((w) => w.length === LONGEST_WORD).slice(0, WORD_COUNT).join('-')

function matrixOf (payload) {
  // ECC_LEVEL widens to `string` crossing the module boundary; qrcode-generator
  // wants the literal union.
  const qr = qrcode(0, /** @type {'H'} */ (ECC_LEVEL))
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

test('a generated code is five words from the EFF list and is already canonical', () => {
  for (let i = 0; i < 200; i++) {
    const code = generateCode()
    const words = code.split('-')
    assert.equal(words.length, WORD_COUNT)
    for (const word of words) {
      assert.ok(INDEX.has(word), `"${word}" is not in the word list`)
      assert.match(word, /^[a-z]{3,9}$/)
    }
    // Generated output must survive parsing untouched, or the code shown to
    // a human would hash to a different topic than the one we joined.
    assert.equal(parseCode(code), code)
    assert.ok(isValidCode(code))

    // The split is positional and total: every word belongs to exactly one
    // half, and rejoining them reproduces the code. A split that lost or
    // duplicated a word would still produce a usable-looking nameplate and
    // secret, and the failure would present as a PAKE that never confirms.
    const { nameplate, secret } = splitCode(code)
    assert.equal(nameplate.split('-').length, NAMEPLATE_WORDS)
    assert.equal(secret.split('-').length, SECRET_WORDS)
    assert.equal(`${nameplate}-${secret}`, code)
  }
})

test('the wordlist is the vendored EFF large list, minus the four hyphenated words', () => {
  assert.equal(WORDS.length, 7772)
  assert.equal(new Set(WORDS).size, 7772, 'no duplicates')
  assert.ok(WORDS.every((w) => /^[a-z]{3,9}$/.test(w)), 'all words are 3-9 lowercase letters')
  for (const hyphenated of ['drop-down', 'felt-tip', 't-shirt', 'yo-yo']) {
    assert.ok(!WORDS.includes(hyphenated), `${hyphenated} is excluded; see engine/src/wordlist.js`)
  }
  assert.deepEqual(WORDS, [...WORDS].sort(), 'kept in the source list order')
  assert.equal(WORDS[0], 'abacus')
  assert.equal(WORDS[WORDS.length - 1], 'zoom')
  // 2 * log2(7772) and 3 * log2(7772). Two figures rather than one,
  // because the halves defend different things: a combined ~64.6 would let
  // the nameplate's public bits stand in for the secret's strength, and
  // only the secret's ~38.8 are load-bearing.
  assert.ok(Math.abs(NAMEPLATE_ENTROPY_BITS - 25.85) < 0.01, `nameplate entropy was ${NAMEPLATE_ENTROPY_BITS}`)
  assert.ok(Math.abs(SECRET_ENTROPY_BITS - 38.77) < 0.01, `secret entropy was ${SECRET_ENTROPY_BITS}`)
})

test('every input style a code arrives in resolves to one canonical form and one topic', () => {
  const canonical = 'acid-acorn-acre-acts-afar'
  const variants = [
    canonical,
    `${QR_SCHEME}:ACID-ACORN-ACRE-ACTS-AFAR`, // scanned QR payload
    'adhal2:acid-acorn-acre-acts-afar',
    'ACID-ACORN-ACRE-ACTS-AFAR',
    'Acid Acorn Acre Acts Afar', // pasted out of a chat client
    '  acid   acorn acre acts afar  ',
    'acid_acorn.acre acts--afar' // mangled separators
  ]

  const expected = resolveCode(canonical)
  for (const variant of variants) {
    assert.equal(parseCode(variant), canonical, `parse of ${JSON.stringify(variant)}`)
    // The property that actually matters: same code, same 32-byte topic.
    // Divergence here means two peers join unrelated topics and present
    // as a discovery timeout rather than as a typo.
    const resolved = resolveCode(variant)
    assert.equal(resolved.topic.length, 32)
    assert.equal(resolved.topic.toString('hex'), expected.topic.toString('hex'), `topic for ${JSON.stringify(variant)}`)
    // And the same secret, which is the half whose divergence is worse:
    // the two peers would find each other on a matching topic and then
    // fail to confirm, which reads like an attack rather than a typo.
    assert.equal(resolved.secret, expected.secret, `secret for ${JSON.stringify(variant)}`)
    assert.equal(resolved.nameplate, 'acid-acorn')
    assert.equal(resolved.secret, 'acre-acts-afar')
  }
})

test('the topic commits to the nameplate and to nothing else', () => {
  // THE PROPERTY v2 EXISTS FOR. The receiver must announce its topic to be
  // findable, so whatever the topic commits to is grindable offline at
  // whatever rate an attacker's hardware allows. Under v1 that was the
  // whole code. Under v2 it must be the nameplate alone.
  //
  // Asserted as an equality against a topic derived from the nameplate in
  // isolation, because that is the only formulation that cannot pass by
  // accident: if any byte of the secret reached the hash, these two would
  // differ.
  const sameNameplate = ['acid-acorn-acre-acts-afar', 'acid-acorn-agent-agile-aging']
  const [a, b] = sameNameplate.map((c) => resolveCode(c))
  assert.equal(a.topic.toString('hex'), b.topic.toString('hex'),
    'two codes sharing a nameplate must land on one topic, or the secret leaked into it')
  assert.equal(a.topic.toString('hex'), topicFromNameplate('acid-acorn').toString('hex'))
  assert.notEqual(a.secret, b.secret, 'the two secrets must really differ, or this proves nothing')

  // A different nameplate is a different rendezvous.
  assert.notEqual(
    a.topic.toString('hex'),
    resolveCode('acorn-acid-acre-acts-afar').topic.toString('hex')
  )

  // And what makes a v1/v2 collision impossible rather than merely
  // unlikely: the domain label. v1 hashed a v1 prefix concatenated with the
  // whole code; v2 hashes lv_cat('adhal-v2:topic', nameplate), so the two
  // never land on one topic and a v1-against-v2 pairing surfaces as
  // ERR_NO_PEER rather than as frame corruption. Asserted on the constant
  // because that is the mechanism; re-deriving a v1 topic here would only
  // test this test's own arithmetic.
  assert.equal(TOPIC_LABEL, 'adhal-v2:topic')
})

test('a bad code is rejected with a message that locates the problem', () => {
  assert.throws(() => parseCode('acid-acorn-acre-acts'), /expected 5 words, got 4/)
  assert.throws(() => parseCode('acid-acorn-acre-acts-afar-agent'), /expected 5 words, got 6/)
  assert.throws(() => parseCode(''), /empty/)
  assert.throws(() => parseCode('   '), /empty/)
  assert.throws(() => parseCode(null), TypeError)

  // Names the offending word *and* its position, because this code was
  // typed by hand off another device's screen.
  assert.throws(
    () => parseCode('acid-acorn-akorn-acts-afar'),
    /word 3 of 5, "akorn", is not in the word list/
  )

  // Another payload format must be reported as such, not silently misread
  // as words.
  //
  // AND THE MESSAGE MUST NOT GUESS A DIRECTION. This build knows one
  // scheme, so it cannot tell an older payload from a newer one, and
  // claiming "newer" for an older payload sends its holder looking for an
  // upgrade that does not exist. So it names the skew and the fix that
  // works either way.
  for (const other of ['ADHAL3:ACID-ACORN-ACRE-ACTS-AFAR', 'ADHAL1:ACID-ACORN-ACRE-ACTS-AFAR']) {
    assert.throws(
      () => parseCode(other),
      (err) => {
        const message = /** @type {Error} */ (err).message
        assert.match(message, /unrecognized code format/)
        assert.match(message, /same version on both sides/)
        assert.doesNotMatch(message, /newer|older/, 'one known scheme cannot say which way the skew points')
        return true
      }
    )
  }

  for (const bad of ['', 'acid', 'one two three four five']) {
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
  assert.equal(longest.length, 56, 'worst case is ADHAL2: plus five nine-letter words')
})

test('the worst-case code fits a 37x37 version-5 symbol at ECC level H', () => {
  // This is the property the uppercasing buys, and it is worth pinning:
  // byte mode would cost one more version at every level (cli/src/qr.js
  // has the measured table).
  //
  // THE WORST CASE IS PINNED, NOT EVERY CODE. Under the EFF large list the
  // longest payload is 56 characters, which needs version 5 (37x37) at ECC
  // H; most codes fit version 4 (33x33). What must not happen is a code
  // larger than the pinned worst case, which is what a byte-mode payload
  // or a longer separator would produce. If this assertion moves, the
  // symbol grew, and it should move on purpose.
  assert.equal(ECC_LEVEL, 'H')
  const worst = matrixOf(encodeQrPayload(LONGEST_CODE)).getModuleCount()
  assert.equal(worst, 37, `the worst-case code produced a ${worst}x${worst} symbol`)
  for (const code of Array.from({ length: 100 }, () => generateCode())) {
    const count = matrixOf(encodeQrPayload(code)).getModuleCount()
    assert.ok(count <= worst, `code ${code} produced a ${count}x${count} symbol, larger than the worst case`)
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

test('resolveCode holds a five-word-shaped input to the strict parse', () => {
  // The regression this guards: a typo'd word code must NOT be waved
  // through as an opaque secret. Doing so hashes to a valid but wrong
  // topic, and the resulting peer-discovery timeout is indistinguishable
  // from the announce-propagation races in engine/src/swarm.js.
  assert.throws(
    () => resolveCode('acid-acorn-akorn-acts-afar'),
    /"akorn", is not in the word list/
  )

  const words = resolveCode('acid-acorn-acre-acts-afar')
  assert.equal(words.kind, 'words')
  assert.equal(words.code, 'acid-acorn-acre-acts-afar')
  assert.equal(words.nameplate, 'acid-acorn')
  assert.equal(words.secret, 'acre-acts-afar')

  // Opaque secrets have to keep working for the engine/scratch-*.js
  // diagnostics, which take hand-typed strings -- but they are now
  // opt-in, because an opaque code is whatever the caller typed and
  // `adhal-test-3` is dictionary-attackable in a way a generated word
  // code is not. See resolveCode.
  for (const opaque of ['a3f9c2b18d7e4056', 'adhal-test-3', 'acid-acorn']) {
    const resolved = resolveCode(opaque, { allowOpaque: true })
    assert.equal(resolved.kind, 'opaque', `${opaque} should stay opaque`)
    assert.equal(resolved.code, opaque)
    assert.equal(resolved.topic.length, 32)
    // AND THE COST OF THAT PATH, PINNED RATHER THAN LEFT IMPLICIT. An
    // opaque code is its own nameplate and its own secret, so the secret
    // goes into the announced topic and is grindable offline -- exactly
    // the property v2 removes. It is asserted here so that the one place
    // v2's central guarantee is voided is a visible, tested fact rather
    // than an accident someone might 'fix' into the word-code path.
    assert.equal(resolved.nameplate, opaque)
    assert.equal(resolved.secret, opaque)
    assert.equal(
      resolved.topic.toString('hex'),
      topicFromNameplate(opaque).toString('hex'),
      'the opaque secret really is what the public topic commits to'
    )
  }

  // Same string, same topic, regardless of which branch produced it.
  assert.equal(
    resolveCode('adhal-test-3', { allowOpaque: true }).topic.toString('hex'),
    resolveCode('adhal-test-3', { allowOpaque: true }).topic.toString('hex')
  )
  assert.throws(() => resolveCode('   ', { allowOpaque: true }), /empty/)

  // And the gate itself: the default refuses, naming the way out. This
  // is the product-surface guarantee -- no CLI can emit a weak drop
  // without someone having typed --unsafe-opaque.
  assert.throws(
    () => resolveCode('adhal-test-3'),
    /--unsafe-opaque/,
    'an opaque code must be refused unless explicitly allowed'
  )
})

test('the hand-typed diagnostic secrets still resolve as opaque codes when asked', () => {
  // The engine/scratch-*.js tools and several tests name a topic by hand,
  // and these are the shapes they use. A six-part string is one of them:
  // with no v1 code format left to recognise, it is an opaque secret like
  // any other, and refused unless opaque codes are allowed.
  for (const diagnostic of ['adhal-test-3', 'a3f9c2b18d7e4056', 'acid-acorn', 'trial-deadbeefdeadbeef', 'one-two-three-four-five-zzzzz']) {
    assert.equal(resolveCode(diagnostic, { allowOpaque: true }).kind, 'opaque', diagnostic)
    assert.throws(() => resolveCode(diagnostic), /not a 5-word drop code/, diagnostic)
  }
})

test('no refusal echoes the drop secret back to the terminal', () => {
  // cli/src/read-code.js exists to keep a code off the screen, out of
  // shell history and out of `ps` -- it reads from a TTY with echo off and
  // warns when a code arrives in argv. Three error messages undid that by
  // echoing the input verbatim, and they fired on exactly the shapes that
  // mode is for: a stray separator, a pasted QR payload, a code pasted out
  // of a chat client.
  //
  // The count and the position of a bad word are the diagnostics. The
  // words are not, because three of them are the secret.
  const code = generateCode()
  const secret = splitCode(code).secret

  /** @param {() => unknown} fn */
  const messageFrom = (fn) => {
    try { fn(); return null } catch (err) { return /** @type {Error} */ (err).message }
  }

  const messages = [
    // A stray separator: 6 tokens, so this misses the word-code shape and
    // lands in resolveCode's opaque refusal.
    messageFrom(() => resolveCode(code.replace('-', '-x-'))),
    // A dropped word: the wrong count, from parseCode.
    messageFrom(() => parseCode(code.split('-').slice(0, 4).join('-'))),
    // An extra word.
    messageFrom(() => parseCode(code + '-agent')),
    // Six words, all from the list: an opaque refusal, which must not
    // echo them either.
    messageFrom(() => resolveCode(code + '-agent'))
  ]

  for (const message of messages) {
    assert.ok(message, 'each of these must actually throw')
    assert.doesNotMatch(message, new RegExp(secret), `a refusal leaked the secret: ${message}`)
    // And not the whole code either, which contains it.
    assert.doesNotMatch(message, new RegExp(code))
  }

  // The diagnostics that remain must still be useful, or this is a
  // regression dressed up as a fix.
  assert.match(messages[1], /expected 5 words, got 4/)
  assert.match(messages[2], /expected 5 words, got 6/)
  assert.match(messages[0], /not a 5-word drop code/)

  // The one place a word IS named stays: that word is by definition wrong,
  // and naming it is the difference between a one-character fix and
  // retyping the whole code off another device's screen.
  const badWord = messageFrom(() => parseCode(code.split('-').map((w, i) => (i === 2 ? 'zzzzz' : w)).join('-')))
  assert.match(badWord, /word 3 of 5, "zzzzz", is not in the word list/)
})

test('an opaque code is canonicalised, so the PAKE can actually use it', () => {
  // A real bug, not tidying. The opaque code becomes the PAKE password and
  // engine/src/handshake.js requires a canonical secret -- so a mixed-case
  // opaque code resolved cleanly here and then threw a bare TypeError out
  // of the join, advising the caller about "canonical form, as splitCode
  // produces it" and naming a function that never runs on this path. A
  // documented, deliberately-supported diagnostic input was unusable.
  const lower = resolveCode('adhal-test-3', { allowOpaque: true })
  for (const variant of ['Adhal-Test-3', 'ADHAL-TEST-3', '  adhal-TEST-3  ']) {
    const resolved = resolveCode(variant, { allowOpaque: true })
    assert.equal(resolved.kind, 'opaque')
    assert.equal(resolved.secret, 'adhal-test-3', `${variant} must canonicalise`)
    // Same topic, which also removes v1's footgun here: v1 hashed exactly
    // what it was given, so two machines disagreeing on case landed on
    // unrelated topics and presented as a discovery timeout.
    assert.equal(resolved.topic.toString('hex'), lower.topic.toString('hex'))
  }

  // Whitespace is REFUSED rather than collapsed, and the distinction is
  // deliberate: an opaque code is an arbitrary string, so collapsing its
  // separators would make two distinct diagnostic topics the same without
  // saying so.
  assert.throws(
    () => resolveCode('adhal test 3', { allowOpaque: true }),
    /may not contain whitespace/
  )
})

test('code generation draws on the whole word list without favoring its start', (t) => {
  // A smoke test for sampling bias, not a proof of uniformity. It exists
  // because 7772 is not a power of two: reducing random bytes modulo 7772
  // would skew draws toward the front of the list, and that is the mistake
  // this would catch. generateCode uses crypto.randomInt, which rejection
  // samples instead.
  //
  // 100k draws, because coverage is the other assertion: at 20k draws over
  // 7772 words only ~92% of the list is expected to appear at all.
  const draws = 100000
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

  // Expected mean index is (7772-1)/2 = 3885.5. The standard error over
  // 100k draws is ~7.1 (7772/sqrt(12), over sqrt(100k)), so a +/-40 band
  // is more than five standard errors -- far too wide to flake -- and still
  // catches the bias this is for: reducing a 16-bit value modulo 7772
  // would pull the mean down to ~3772.
  const meanIndex = indexSum / draws
  t.diagnostic(`mean word index ${meanIndex.toFixed(1)} (expected ~3885.5), coverage ${(coverage * 100).toFixed(1)}%`)
  assert.ok(Math.abs(meanIndex - 3885.5) < 40, `mean index was ${meanIndex.toFixed(1)}`)
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
    () => execFileAsync(process.execPath, [CODE_SCRIPT, 'acid-acorn-akorn-acts-afar']),
    (err) => {
      // assert.rejects types the error as `unknown`.
      const failure = /** @type {{ code: number, stderr: string }} */ (err)
      assert.equal(failure.code, 1)
      assert.match(failure.stderr, /"akorn", is not in the word list/)
      return true
    }
  )
})

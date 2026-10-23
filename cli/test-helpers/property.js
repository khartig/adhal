'use strict'

// Property-based testing with no dependency (Q-06, and decision 6 in
// docs/history/WORK-RECORD.md, which kept the fuzz harness dependency-free
// for the same reason: a test tool is part of the supply chain too).
//
// A property is a claim about every input of some shape: "however the
// bytes are split, the decoder yields the same frames". `check` draws
// inputs from a generator, runs the property on each, and on a failure
// SHRINKS the input -- tries smaller versions of it, keeping any that
// still fails -- so the report shows a counterexample a person can read
// rather than the 3 MB one that happened to be drawn first.
//
// HOW SHRINKING WORKS HERE. A generator returns a tree: a value, and a
// function listing smaller trees to try in its place. Shrinking walks down
// it greedily. Because `map` and `tuple` build trees out of trees, a
// shrunk value is always one the generator could have produced, so the
// property is never handed an input outside its own precondition. That is
// the whole reason for trees over shrinking values after the fact.
//
// Budget and replay, the same shape as the fuzz harness's:
//
//   ADHAL_PROPERTY_RUNS=<n>     inputs per property (default 100)
//   ADHAL_PROPERTY_SEED=<hex>   replay a run; a failure prints it
//
// Each property's generator is seeded from the run's seed and the
// property's own label, so one property replays alone with the same seed.
//
// Not in cli/test/ for the reason duplex-pair.js gives.

const crypto = require('node:crypto')
const util = require('node:util')
const { rng } = require('./rng')

const RUNS = Number(process.env.ADHAL_PROPERTY_RUNS || 100)
const SEED = process.env.ADHAL_PROPERTY_SEED || crypto.randomBytes(4).toString('hex')
const MAX_SHRINK_STEPS = 1000

/**
 * @template T
 * @typedef {{ value: T, shrinks: () => Iterable<Tree<T>> }} Tree
 */
/**
 * @template T
 * @typedef {(r: ReturnType<typeof rng>) => Tree<T>} Gen
 */

/** @template T @param {T} value @param {() => Iterable<Tree<T>>} [shrinks] @returns {Tree<T>} */
const tree = (value, shrinks = () => []) => ({ value, shrinks })

/** @template T, U @param {Tree<T>} t @param {(v: T) => U} f @returns {Tree<U>} */
function mapTree (t, f) {
  return tree(f(t.value), function * () {
    for (const c of t.shrinks()) yield mapTree(c, f)
  })
}

/** An integer tree shrinking toward `target`. @param {number} n @param {number} target @returns {Tree<number>} */
function intTree (n, target) {
  return tree(n, function * () {
    if (n === target) return
    yield intTree(target, target)
    for (let d = Math.trunc((n - target) / 2); d !== 0; d = Math.trunc(d / 2)) yield intTree(n - d, target)
  })
}

/**
 * A list tree: shrinks by dropping halves, then single elements, then by
 * shrinking each element in place.
 * @template T @param {Tree<T>[]} items @param {number} min @returns {Tree<T[]>}
 */
function listTree (items, min) {
  return tree(items.map((t) => t.value), function * () {
    const n = items.length
    for (let size = n >> 1; size >= 1; size >>= 1) {
      for (let start = 0; start + size <= n; start += size) {
        if (n - size >= min) yield listTree([...items.slice(0, start), ...items.slice(start + size)], min)
      }
    }
    for (let i = 0; i < n; i++) {
      for (const c of items[i].shrinks()) yield listTree([...items.slice(0, i), c, ...items.slice(i + 1)], min)
    }
  })
}

const gen = {
  /** @template T @param {T} v @returns {Gen<T>} */
  constant: (v) => () => tree(v),

  /**
   * An integer in [min, max], shrinking toward the bound nearest zero.
   * Half the draws land on or beside a bound, where off-by-ones live.
   * @param {number} min @param {number} max @returns {Gen<number>}
   */
  int: (min, max) => (r) => {
    const span = max - min + 1
    const edges = [min, min + 1, max - 1, max].filter((v) => v >= min && v <= max)
    const n = r.int(2) === 0 ? r.pick(edges) : min + Math.floor(r.next() * span)
    return intTree(n, min <= 0 && max >= 0 ? 0 : min)
  },

  /** One of `list`, shrinking toward its first element. @template T @param {T[]} list @returns {Gen<T>} */
  element: (list) => (r) => mapTree(intTree(r.int(list.length), 0), (i) => list[i]),

  /** @template T @param {Gen<T>} g @param {{ min?: number, max: number }} o @returns {Gen<T[]>} */
  array: (g, { min = 0, max }) => (r) => {
    const n = min + r.int(max - min + 1)
    return listTree(Array.from({ length: n }, () => g(r)), min)
  },

  /**
   * Up to `max` bytes. Small buffers shrink byte by byte; large ones only
   * by length, which is what a large counterexample needs and costs one
   * property run per halving rather than one per byte.
   * @param {{ min?: number, max: number }} o @returns {Gen<Buffer>}
   */
  bytes: ({ min = 0, max }) => (r) => {
    const n = min + r.int(max - min + 1)
    if (n <= 64) return mapTree(listTree(Array.from({ length: n }, () => intTree(r.int(256), 0)), min), (a) => Buffer.from(a))
    const data = r.bytes(n)
    /** @param {Buffer} b @returns {Tree<Buffer>} */
    const lengths = (b) => tree(b, function * () {
      for (let len = min; len < b.length; len = len === 0 ? 1 : len * 2) yield lengths(b.subarray(0, len))
    })
    return lengths(data)
  },

  /** @param {Gen<any>[]} gens @returns {Gen<any[]>} */
  tuple: (...gens) => (r) => {
    /** @param {Tree<any>[]} ts @returns {Tree<any[]>} */
    const tupleTree = (ts) => tree(ts.map((t) => t.value), function * () {
      for (let i = 0; i < ts.length; i++) {
        for (const c of ts[i].shrinks()) yield tupleTree([...ts.slice(0, i), c, ...ts.slice(i + 1)])
      }
    })
    return tupleTree(gens.map((g) => g(r)))
  },

  /** @template T, U @param {Gen<T>} g @param {(v: T) => U} f @returns {Gen<U>} */
  map: (g, f) => (r) => mapTree(g(r), f),

  /** One of the generators, chosen at random. @param {Gen<any>[]} gens @returns {Gen<any>} */
  oneOf: (...gens) => (r) => r.pick(gens)(r)
}

/** @param {(v: any) => any} property @param {any} value */
async function failure (property, value) {
  try {
    await property(value)
    return null
  } catch (err) {
    return err
  }
}

/**
 * Runs `property` on `runs` inputs from `g`. On a failure, shrinks it and
 * throws an assertion naming the seed, the shrunk input, and the error.
 * @template T
 * @param {string} label
 * @param {Gen<T>} g
 * @param {(value: T) => void | Promise<void>} property
 * @param {{ runs?: number }} [o]
 */
async function check (label, g, property, { runs = RUNS } = {}) {
  const r = rng(crypto.createHash('sha256').update(`${SEED}:${label}`).digest('hex'))
  for (let run = 0; run < runs; run++) {
    const t = g(r)
    const err = await failure(property, t.value)
    if (!err) continue

    let current = t
    let currentErr = err
    let steps = 0
    shrinking: while (steps < MAX_SHRINK_STEPS) {
      for (const c of current.shrinks()) {
        const e = await failure(property, c.value)
        if (e) {
          current = c
          currentErr = e
          steps++
          continue shrinking
        }
      }
      break
    }
    const shown = util.inspect(current.value, { depth: 6, maxArrayLength: 32, maxStringLength: 200, breakLength: 100 })
    const message = currentErr && currentErr.message ? currentErr.message : String(currentErr)
    const out = new Error(
      `property "${label}" failed on run ${run + 1} of ${runs} ` +
      `(ADHAL_PROPERTY_SEED=${SEED} replays it), shrunk in ${steps} steps to:\n  ${shown}\n${message}`
    )
    out.cause = currentErr
    throw out
  }
}

module.exports = { gen, check, RUNS, SEED }

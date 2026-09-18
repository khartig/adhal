'use strict'

// Turns a TransferError code into a sentence worth reading.
//
// The engine's own message already says what happened; what it cannot say
// is what the person at the terminal should do about it, because that
// depends on being a CLI. This file is that layer, and it is one file for
// the same reason cli/src/signals.js is: the alternative is the same
// mapping pasted into four transport scripts, where the copy that drifts
// is always the one nobody was looking at.
//
// The distinction each line is protecting: before item 5, every one of
// these arrived as `error: <something>` and several arrived as nothing at
// all. "The peer cancelled", "the bytes are wrong" and "the punch died"
// are three different situations with three different responses, and
// telling them apart is the whole point of the item.

/** @param {any} err */
function isLocalCancellation (err) {
  return err && (err.name === 'AbortError' || err.code === 'ABORT_ERR')
}

/** @param {any} err */
function isPeerCancellation (err) {
  return err && err.code === 'ERR_CANCELLED_PEER'
}

/**
 * Either end deliberately stopped. Nothing failed, so nothing about the
 * socket's subsequent death is worth reporting.
 * @param {any} err
 */
function isCancellation (err) {
  return isLocalCancellation(err) || isPeerCancellation(err)
}

/**
 * A single line, already prefixed by the caller's label.
 * @param {any} err
 * @returns {string}
 */
function describeError (err) {
  const code = err && err.code

  switch (code) {
    case 'ABORT_ERR':
      return `cancelled${typeof err.bytes === 'number' ? ` after ${err.bytes} bytes` : ''}. The peer was told, so it will report a deliberate cancel rather than a dropped connection.`

    case 'ERR_CANCELLED_PEER':
      // Verbatim, but the engine has already capped it at 256 bytes and
      // stripped control characters -- it is a string chosen by the other
      // end and it is about to be printed into a terminal.
      return err.peerReason
        ? `the peer cancelled the transfer: ${err.peerReason}`
        : 'the peer cancelled the transfer.'

    case 'ERR_HASH_MISMATCH':
      return `FAILED: the received file does not match the sender's digest, so it was discarded and nothing was saved. ` +
        `Expected ${err.expected}, computed ${err.actual}. This is corruption or a bug, not a network timeout -- do not retry blindly.`

    case 'ERR_SIZE_MISMATCH':
      return `FAILED: the transfer did not match the size its manifest declared (${err.bytes} bytes against ${err.size}). Nothing was saved.`

    case 'ERR_UNSAFE_NAME':
      return `FAILED: refused the peer's filename ${JSON.stringify(err.declaredName)} because it points outside the output directory. Nothing was written.`

    case 'ERR_MANIFEST_INVALID':
      return `FAILED: the peer's manifest is invalid${err.field ? ` (field: ${err.field})` : ''}. ${err.message}`

    case 'ERR_PROTOCOL':
      return `FAILED: protocol error. ${err.message}`

    case 'ERR_CONNECTION':
      return `FAILED: the connection closed before the transfer finished (${err.bytes} bytes received). The partial file was discarded.`

    case 'ERR_NO_PEER':
    case 'ERR_NO_HANDSHAKE':
      // These already carry long, carefully-worded diagnostics from
      // engine/src/swarm.js. Repeating them here would only let the two
      // wordings drift apart.
      return err.message

    default:
      return `error: ${err && err.message ? err.message : String(err)}`
  }
}

module.exports = { describeError, isLocalCancellation, isPeerCancellation, isCancellation }

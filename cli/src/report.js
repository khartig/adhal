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
// The distinction each line is protecting: before the failure-reporting
// work, every one of these arrived as `error: <something>` and several
// arrived as nothing at all. "The peer cancelled", "the bytes are wrong"
// and "the punch died" are three different situations with three
// different responses, and telling them apart is the whole point.
//
// Switched on `err.code`, never on the message. That is load-bearing
// rather than tidy: the messages here are free to be reworded, and
// PROTOCOL.md section 10 makes the codes the contract precisely because
// this project's own measurement harness once classified failures by
// regex-matching prose.

const { displayName } = require('@quay/engine')

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
      if (err.reportedBy === 'receiver') {
        return `FAILED: the receiver confirmed a digest that is not the one sent (sent ${err.expected}, it reports ${err.actual}). ` +
          'An honest receiver refuses a file that does not match; this one claimed it kept it. Treat the receiving side as broken.'
      }
      return `FAILED: the received file does not match the sender's digest, so it was discarded and nothing was saved. ` +
        `Expected ${err.expected}, computed ${err.actual}. This is corruption or a bug, not a network timeout -- do not retry blindly.`

    case 'ERR_SIZE_MISMATCH':
      return `FAILED: the transfer did not match the size its manifest declared (${err.bytes} bytes against ${err.size}). Nothing was saved.`

    case 'ERR_UNSAFE_NAME':
      // THE OLD WORDING WAS A GUESS, AND USUALLY THE WRONG ONE. It said
      // the name "points outside the output directory" for every
      // refusal, when traversal is only one of the reasons: a NUL byte,
      // control characters, a bidi override, an over-long name and an
      // empty one all arrive here too, and telling someone their
      // 300-character filename escaped the directory sends them looking
      // for an attack that did not happen. The engine already computes
      // the specific reason -- printing it is strictly better than
      // re-deriving a worse one here.
      return `FAILED: refused the peer's filename ${JSON.stringify(displayName(err.declaredName))}: ${err.detail || 'it is not a name we are willing to write'}. Nothing was written.`

    case 'ERR_MANIFEST_INVALID':
      return `FAILED: the peer's manifest is invalid${err.field ? ` (field: ${err.field})` : ''}. ${err.message}`

    case 'ERR_PROTOCOL':
      return `FAILED: protocol error. ${err.message}`

    case 'ERR_CONNECTION':
      // The sender's two cases. `phase` is only set there; the receiver's
      // wording below predates it and still describes the receiver.
      if (err.phase === 'result') {
        return 'FAILED: every byte was sent, but the receiver disconnected before confirming the file. ' +
          'Whether it was saved is unknown -- check the receiver\'s output before sending again.'
      }
      if (err.phase === 'send') {
        return `FAILED: the receiver disconnected after ${err.bytes} of ${err.size} bytes were sent.`
      }
      return `FAILED: the connection closed before the transfer finished (${err.bytes} bytes received). The partial file was discarded.`

    case 'ERR_RECEIVER_FAILED':
      return err.peerReason
        ? `FAILED: the receiver got every byte but could not keep the file: ${err.peerReason}`
        : 'FAILED: the receiver got every byte but could not keep the file.'

    case 'ERR_STALLED':
      if (err.phase === 'result') {
        return `FAILED: ${err.message}. Check the receiver's output before sending again.`
      }
      return `FAILED: ${err.message}.`

    case 'ERR_ATTEMPT_CAP':
      // THE ONLY CASE IN THIS FILE THAT MEANS SOMEONE WAS GUESSING.
      // Everything else here is a fault; this one is a report, and it is
      // the reason PROTOCOL.md section 10 singles it out. Without this
      // case it would fall through to the generic `error: <message>` and
      // get the least prose of any failure -- which is precisely backwards
      // for the only outcome a human has to act on beyond retrying.
      //
      // Three things have to be said, and in this order. What happened,
      // because "burned" is not self-explanatory. That the code is spent,
      // because the instinct is to retry with it and that hands the
      // guesser its next hundred attempts. And that the handover route may
      // be the problem, because a guesser who knew the nameplate got it
      // from somewhere.
      return `FAILED: this drop was burned after ${err.attempts} failed attempts to confirm the code` +
        `${typeof err.max === 'number' ? ` (the limit is ${err.max})` : ''}. ` +
        'That is not a network problem: somebody was guessing the secret. Nothing was ' +
        'transferred. Do NOT retry with the same code -- it is spent, and reusing it ' +
        'would give them another hundred guesses. Generate a new one, and consider ' +
        'whether the way you shared the last one is how they found it.'

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

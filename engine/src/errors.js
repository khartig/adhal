'use strict'

// One error type for every way a transfer can fail, each carrying a
// machine-readable `.code`.
//
// WHY THIS IS NOT MERELY TIDINESS. `engine/scratch-trials.js` -- the
// harness that produced every reliability number this project has claimed
// -- classified failures by regex-matching error *messages*. The project's
// own measurement instrument was therefore coupled to prose: rewording a
// sentence silently re-buckets a result, and its loudest output ("N HASH
// MISMATCH(ES) ... stop feature work") hung on a string comparison. Codes
// make that coupling explicit, checkable, and cheap to keep honest.
//
// The codes, and what each one means for whoever is reading the log:
//
//   ABORT_ERR             we cancelled, locally. Not a failure.
//   ERR_CANCELLED_PEER    they cancelled. Also not a failure, and above
//                         all not a network error -- telling those two
//                         apart is the headline of the failure-reporting work.
//   ERR_HASH_MISMATCH     the bytes are wrong. A correctness bug or a
//                         corrupting path; never retried silently.
//   ERR_SIZE_MISMATCH     the peer sent more, or fewer, bytes than its own
//                         manifest declared.
//   ERR_UNSAFE_NAME       the manifest's name is not one we will write:
//                         traversal, a control character, a bidi
//                         override, empty, or too long. `.detail` says
//                         which -- do not re-guess it downstream.
//   ERR_MANIFEST_INVALID  a manifest field failed validation.
//   ERR_STALLED           the peer proved it knows the code and then
//                         stopped talking. Distinct from ERR_CONNECTION
//                         on purpose: the socket is fine, the peer is
//                         not sending. A slow loris looks like this.
//   ERR_NO_SPACE          the declared size does not fit on the disk.
//                         Refused before anything is opened, so the
//                         sender is not made to upload it first.
//   ERR_EXISTS            the file could not be landed without
//                         destroying one we did not create.
//   ERR_PROTOCOL          unknown tag, oversize frame, out-of-order frame.
//   ERR_CONNECTION        the socket closed before the transfer finished.
//                         On the sender, "finished" means the receiver's
//                         RESULT arrived: a close after the last byte was
//                         sent but before RESULT carries `phase: 'result'`,
//                         and means the receiver's outcome is unknown.
//   ERR_RECEIVER_FAILED   the receiver got every byte and could not keep
//                         the file -- its digest disagreed, or landing it
//                         failed. Reported to the sender in RESULT{error};
//                         `.peerReason` is the receiver's own sentence.
//   ERR_DECLINED          the receiver refused the offer before any file
//                         byte moved: an unsafe name, too large, no
//                         space, or a person or policy said no. Sent to
//                         the sender as DECLINE{reason, code}; `.peerReason`
//                         is the receiver's sentence and `.declineCode` its
//                         code, for automation to switch on. The receiver
//                         itself reports the specific code it declined for.
//   ERR_NO_PEER           join timed out having seen nobody.
//   ERR_NO_HANDSHAKE      join timed out having seen peers that never
//                         completed the handshake. A different
//                         investigation entirely -- see swarm.js.
//   ERR_ATTEMPT_CAP       the drop was burned after N failed attempts to
//                         confirm the secret. THE ONLY CODE HERE THAT
//                         MEANS SOMEONE WAS GUESSING: everything else in
//                         this list is a fault, and this one is a report.
//                         See attempts.js and PROTOCOL.md section 6, and
//                         note that it deliberately reverses v1's rule
//                         that an attacker must not be able to end a drop
//                         by connecting and failing -- a denial of service
//                         is a better failure than a silent compromise
//                         against ~38.8 bits.
//
// `name` stays 'TransferError' for everything except a local abort, which
// uses Node's own 'AbortError'/'ABORT_ERR' pair so that `signal.reason`
// and generic abort handling elsewhere in Node keep working unchanged.

class TransferError extends Error {
  /**
   * @param {string} code one of the codes above
   * @param {string} message human-readable, and free to be reworded --
   *   nothing should ever match on it
   * @param {Record<string, any>} [extra] code-specific detail (`bytes`,
   *   `expected`, `declaredName`, ...), copied onto the error as-is
   */
  constructor (code, message, extra = {}) {
    super(message)
    this.name = 'TransferError'
    this.code = code
    Object.assign(this, extra)
  }
}

// Node's abort shape, not ours, and deliberately so: a caller that already
// handles AbortError from any other Node API handles this one too.
/**
 * @param {number} bytes how far the transfer had got
 * @param {any} [cause] the signal's own `reason`, if it had one
 */
function abortError (bytes, cause) {
  const err = new TransferError('ABORT_ERR', 'transfer cancelled locally', { bytes })
  err.name = 'AbortError'
  if (cause !== undefined) err.cause = cause
  return err
}

module.exports = { TransferError, abortError }

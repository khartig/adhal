'use strict'

const fs = require('fs')
const path = require('path')
const crypto = require('crypto')
const { encodeFrame, FrameDecoder } = require('./frame')

// 64 KB balances syscall/frame overhead against memory use; revisit once
// item 6 (resume) and large-file testing (doc section 9, item 6) land.
const DEFAULT_CHUNK_SIZE = 64 * 1024

function hashFile (filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256')
    const stream = fs.createReadStream(filePath)
    stream.on('data', (chunk) => hash.update(chunk))
    stream.on('end', () => resolve(hash.digest('hex')))
    stream.on('error', reject)
  })
}

// Sends one manifest frame (JSON) followed by the file as raw chunk frames.
// `socket` is any writable+readable duplex stream (net.Socket for item 1;
// a Hyperswarm/Protomux channel from item 2 onward).
async function sendFile (socket, filePath, { chunkSize = DEFAULT_CHUNK_SIZE } = {}) {
  const stat = await fs.promises.stat(filePath)
  const sha256 = await hashFile(filePath)

  const manifest = {
    type: 'manifest',
    name: path.basename(filePath),
    size: stat.size,
    chunkSize,
    sha256
  }

  socket.write(encodeFrame(Buffer.from(JSON.stringify(manifest), 'utf8')))

  // A raw TCP net.Socket (item 1) tolerates ignoring write()'s backpressure
  // signal because the OS gives it deep send buffers. Hyperswarm's
  // encrypted duplex (item 2+) does not -- blasting writes without
  // pausing on a false return / waiting for 'drain' overwhelms it and the
  // connection resets partway through a multi-MB file. Pause/resume the
  // read stream to respect it.
  await new Promise((resolve, reject) => {
    const readStream = fs.createReadStream(filePath, { highWaterMark: chunkSize })

    readStream.on('data', (chunk) => {
      const ok = socket.write(encodeFrame(chunk))
      if (!ok) {
        readStream.pause()
        socket.once('drain', () => readStream.resume())
      }
    })
    readStream.on('end', resolve)
    readStream.on('error', reject)
    socket.on('error', reject)
  })

  return { name: manifest.name, size: manifest.size, sha256 }
}

// Reads manifest + chunk frames off `socket`, writes the file into
// `outputDir`, and resolves once the declared size has been received and
// hashed. Full-file hash verification (comparing against the manifest's
// sha256) is the caller's job, matching the doc's v1 data path step 6.
/**
 * @param {NodeJS.EventEmitter & { removeListener: Function, pause?: Function, resume?: Function }} socket
 * @param {string} outputDir
 * @param {{ onManifest?: (manifest: any) => void, pending?: Buffer | null }} [options]
 *   `pending` is any payload the readiness handshake read off the socket
 *   before handing it over -- see acceptOnce in ./swarm.js, which pauses
 *   the socket and returns leftover bytes rather than swallowing them.
 */
function receiveFile (socket, outputDir, { onManifest, pending } = {}) {
  return new Promise((resolve, reject) => {
    let manifest = null
    let writeStream = null
    let hash = null
    let received = 0
    let outputPath = null
    let settled = false

    const decoder = new FrameDecoder((payload) => {
      if (settled) return

      if (!manifest) {
        try {
          manifest = JSON.parse(payload.toString('utf8'))
        } catch (err) {
          fail(new Error(`invalid manifest frame: ${err.message}`))
          return
        }
        if (manifest.type !== 'manifest') {
          fail(new Error('expected manifest frame first'))
          return
        }

        outputPath = path.join(outputDir, manifest.name)
        writeStream = fs.createWriteStream(outputPath)
        hash = crypto.createHash('sha256')

        if (onManifest) onManifest(manifest)
        if (manifest.size === 0) finalize()
        return
      }

      received += payload.length
      hash.update(payload)
      writeStream.write(payload)

      if (received >= manifest.size) finalize()
    })

    function finalize () {
      if (settled) return
      settled = true
      socket.removeListener('data', onData)
      writeStream.end(() => {
        resolve({
          name: manifest.name,
          size: manifest.size,
          sha256: hash.digest('hex'),
          path: outputPath
        })
      })
    }

    function fail (err) {
      if (settled) return
      settled = true
      socket.removeListener('data', onData)
      reject(err)
    }

    function onData (chunk) {
      try {
        decoder.push(chunk)
      } catch (err) {
        fail(err)
      }
    }

    socket.on('data', onData)
    socket.on('error', fail)

    // Feed the handshake's leftover bytes through the same path as live
    // data, before resuming, so frame order is preserved.
    if (pending && pending.length > 0) onData(pending)
    // acceptOnce paused the socket to hold the gap between resolving and
    // this listener being attached. Harmless when it never paused (item
    // 1's plain TCP path passes no `pending` and does not pause).
    if (typeof socket.resume === 'function') socket.resume()
  })
}

module.exports = { sendFile, receiveFile, hashFile, DEFAULT_CHUNK_SIZE }

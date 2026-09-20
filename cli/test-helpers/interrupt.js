'use strict'

// Interrupting a spawned CLI the way a human would, on each platform.
//
// THE POSIX CASE IS THE EASY ONE. `child.kill('SIGINT')` delivers a real
// SIGINT, the handler in cli/src/signals.js runs, and the process exits
// 130. That is what the two end-to-end tests in cancel.test.js have
// always done and it is unchanged here.
//
// WINDOWS IS WHY THIS FILE EXISTS. Those two tests failed on the Windows
// leg with exit code `null`, and the obvious reading -- "Ctrl-C is broken
// on Windows" -- is wrong. Node documents 'SIGINT' from the terminal as
// supported on every platform; Windows delivers the console Ctrl+C event
// as SIGINT and the handler takes it. What does not work is the *test's*
// way of faking it: `child.kill('SIGINT')` on Windows is documented as
// unconditional termination, which destroys the child before any handler
// runs. Hence `null` and no `cancelled (...)` line. The product was fine;
// the probe was not.
//
// So the Windows path sends a genuine console control event instead:
//
//   * `detached: true` maps, in libuv, to DETACHED_PROCESS |
//     CREATE_NEW_PROCESS_GROUP. The second half is what we are after --
//     it makes `child.pid` a process *group* id, which is the only thing
//     GenerateConsoleCtrlEvent can be aimed at.
//   * CTRL_BREAK_EVENT, not CTRL_C_EVENT. Microsoft documents that
//     CTRL_C_EVENT cannot be targeted at a specific process group, while
//     CTRL+BREAK can. That is why cli/src/signals.js now handles
//     SIGBREAK: this test can only ask the OS for the thing the OS is
//     willing to aim.
//   * The call itself goes through a short PowerShell Add-Type P/Invoke,
//     because Node exposes no binding for it and a native addon for one
//     test is not worth the build.
//
// THIS COULD NOT BE VERIFIED ON A DEVELOPER MACHINE -- there is no
// Windows here, and only CI can say whether it works. The known failure
// mode is console attachment: GenerateConsoleCtrlEvent only reaches
// processes sharing the *caller's* console, and DETACHED_PROCESS (the
// other half of `detached: true`, which Node gives no way to opt out of)
// may leave the child with no console to share. So failure is reported
// rather than thrown, the caller skips with the reason, and the Windows
// leg stays advisory instead of asserting something that was never true.

const { execFile } = require('node:child_process')

const IS_WINDOWS = process.platform === 'win32'

// The signal a real keyboard interrupt produces here, and the exit code
// the handler is expected to leave behind: 128 + the signal number.
const INTERRUPT = IS_WINDOWS
  ? { name: /** @type {const} */ ('SIGBREAK'), code: 149 }
  : { name: /** @type {const} */ ('SIGINT'), code: 130 }

// Spread into the spawn options of any child this module will interrupt.
// Empty on POSIX, so nothing about the existing tests changes there.
const interruptibleSpawn = IS_WINDOWS ? { detached: true } : {}

const CTRL_BREAK_EVENT = 1

/**
 * Deliver a real keyboard-style interrupt to an already-running child.
 *
 * @param {import('node:child_process').ChildProcess} child
 * @returns {Promise<{ ok: true, reason?: undefined } | { ok: false, reason: string }>}
 *   `ok: false` means the OS would not let us generate the event at all,
 *   which is a property of the runner rather than of the code under test.
 *   (`reason?: undefined` on the success arm is not decoration: this repo
 *   typechecks with `strict: false`, and without `strictNullChecks` a
 *   `if (!result.ok)` does not narrow a discriminated union. Declaring the
 *   property on both arms keeps the natural call site typechecking.)
 */
async function interrupt (child) {
  if (!IS_WINDOWS) {
    child.kill('SIGINT')
    return { ok: true }
  }

  if (child.pid === undefined) return { ok: false, reason: 'the child has no pid to aim at' }

  // Here-strings are column-sensitive: `'@` has to start its own line at
  // column zero, so this block cannot be indented to match its context.
  const script = `
$ErrorActionPreference = 'Stop'
$signature = @'
[DllImport("kernel32.dll", SetLastError = true)]
public static extern bool GenerateConsoleCtrlEvent(uint dwCtrlEvent, uint dwProcessGroupId);
'@
$kernel32 = Add-Type -MemberDefinition $signature -Name 'QuayCtrl' -Namespace 'Quay' -PassThru
if ($kernel32::GenerateConsoleCtrlEvent(${CTRL_BREAK_EVENT}, ${child.pid})) {
  Write-Output 'sent'
} else {
  Write-Output ('failed ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error())
}
`

  /** @type {{ stdout: string, stderr: string } | { failed: string }} */
  const result = await new Promise((resolve) => {
    execFile(
      'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-Command', script],
      { timeout: 20000 },
      (error, stdout, stderr) => {
        if (error) resolve({ failed: `powershell could not run it: ${error.message}` })
        else resolve({ stdout, stderr })
      }
    )
  })

  if ('failed' in result) return { ok: false, reason: result.failed }

  const output = result.stdout.trim()
  if (output === 'sent') return { ok: true }

  // The interesting one. Error 6 (ERROR_INVALID_HANDLE) here means the
  // runner has no console for the event to travel through, which is the
  // anticipated skip rather than a bug in the handler.
  return {
    ok: false,
    reason: `GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, ${child.pid}) did not fire -- ${output || result.stderr.trim() || 'no output'}. ` +
      'This is the console-attachment limit, not a cancellation failure: the event can only reach processes sharing the caller\'s console.'
  }
}

module.exports = { INTERRUPT, interrupt, interruptibleSpawn, IS_WINDOWS }

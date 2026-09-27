'use strict'

// Pressing Ctrl-C at a spawned CLI, for real, on each platform.
//
// POSIX IS THE EASY CASE. `child.kill('SIGINT')` delivers a real SIGINT,
// the handler in cli/src/signals.js runs, and the process exits 130. That
// is what the end-to-end tests in cancel.test.js have always done and it
// is untouched here.
//
// WINDOWS IS WHY THIS FILE EXISTS, and the reasoning is written down
// because three plausible-looking approaches are provably wrong.
//
// 1. `child.kill('SIGINT')` cannot work. libuv's uv__kill maps SIGINT,
//    SIGTERM, SIGKILL and SIGQUIT alike onto TerminateProcess and returns
//    ENOSYS for anything else; it never generates a console control
//    event. The child dies before a handler runs, which is why these
//    tests saw exit code `null`. That is the probe failing, not the
//    product: Windows delivers a console Ctrl+C to a real SIGINT handler.
//
// 2. `detached: true` plus GenerateConsoleCtrlEvent aimed at `child.pid`
//    cannot work either, and this one cost a CI round. libuv turns
//    UV_PROCESS_DETACHED into `DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP`,
//    and DETACHED_PROCESS leaves the child with no console at all ("The
//    new process can call the AllocConsole function at a later time").
//    Console control events only reach processes attached to a console,
//    so there was nobody to receive one -- yet the call returned TRUE,
//    which is the trap. A TRUE return means the call was well formed, not
//    that anything got the signal. Node offers no way out of this bind:
//    CREATE_NEW_PROCESS_GROUP, the flag that would make `child.pid` a
//    targetable group id while keeping a console, is only reachable
//    bundled with DETACHED_PROCESS (nodejs/node#21825). Hence a plain
//    spawn, and an event aimed at a console rather than a process group.
//
// 3. CTRL_BREAK_EVENT is the wrong event to send from here, even though
//    it is the one that can be aimed at a specific group. Microsoft:
//    "CTRL+BREAK is always treated as a signal", and the only documented
//    way for the sender to spare itself -- SetConsoleCtrlHandler(NULL,
//    TRUE) -- "causes the calling process to ignore CTRL+C signals", C
//    only. Sending a break into a console we are attached to would run
//    our own default handler, i.e. ExitProcess, and a signaller killed by
//    its own signal reports failure for a delivery that worked. So
//    CTRL_C_EVENT it is, which is what a human presses anyway, arrives as
//    SIGINT, and makes the Windows expectations identical to POSIX.
//
// What remains is a property of the machine, not of this code: does the
// child land in a console of its own, or in the one the test runner is
// sitting in? A console process whose parent has no console gets a fresh
// console; otherwise it inherits its parent's. Firing into a shared
// console would hit the runner, pnpm and the shell as well and take the
// suite down, so this helper *measures* instead of assuming -- it borrows
// the child's console, enumerates it with GetConsoleProcessList, and only
// fires when nothing but the child is in there.
//
// HOW MUCH OF THIS IS ACTUALLY TESTED, given there is no Windows here.
// The script below was run in a Linux PowerShell container with the five
// kernel32 entry points replaced by a mock: its syntax parses, the
// DllImport block really compiles under Add-Type, and each branch was
// exercised -- no console, shared console, unreadable list, buffer too
// small, generate failed, and the happy path. The one that matters most
// is the negative: in every case except an isolated console the mock
// recorded no event generated at all, so the refusal to signal a console
// we share is a measured property rather than an intention.
//
// What that cannot cover is Win32 itself: whether the child lands in its
// own console, whether the event is delivered, and whether Windows
// PowerShell 5.1 (`powershell.exe`, what the runner has) behaves like the
// 7.4 used for the mock run. Only CI can say. So an undeliverable event
// is reported, never thrown, and the reason carries the console's process
// list -- which turns a skip into a measurement of which world we are in.

const { execFile } = require('node:child_process')

const IS_WINDOWS = process.platform === 'win32'

// CTRL_C_EVENT. The only group id it accepts is 0 ("the signal is
// generated in all processes that share the console of the calling
// process"), which is exactly the scope the check below establishes.
const CTRL_C_EVENT = 0
const ALL_IN_THIS_CONSOLE = 0

/**
 * Borrow the child's console, refuse to fire unless the child is alone in
 * it, and otherwise raise a genuine Ctrl+C there.
 *
 * Here-strings are column-sensitive -- `'@` has to begin its own line at
 * column zero -- so this block cannot be indented to match its context.
 *
 * `$PID` below is PowerShell's own process id; the child's is
 * interpolated by JavaScript before PowerShell ever sees the script.
 *
 * @param {number} childPid
 */
function ctrlCScript (childPid) {
  return `
$ErrorActionPreference = 'Stop'
$signature = @'
[DllImport("kernel32.dll", SetLastError = true)] public static extern bool FreeConsole();
[DllImport("kernel32.dll", SetLastError = true)] public static extern bool AttachConsole(uint dwProcessId);
[DllImport("kernel32.dll", SetLastError = true)] public static extern bool SetConsoleCtrlHandler(IntPtr handlerRoutine, bool add);
[DllImport("kernel32.dll", SetLastError = true)] public static extern bool GenerateConsoleCtrlEvent(uint dwCtrlEvent, uint dwProcessGroupId);
[DllImport("kernel32.dll", SetLastError = true)] public static extern uint GetConsoleProcessList(uint[] lpdwProcessList, uint dwProcessCount);
'@
$k32 = Add-Type -MemberDefinition $signature -Name 'AdhalCtrl' -Namespace 'Adhal' -PassThru

# A process can be attached to at most one console, so drop whatever we
# inherited before borrowing the child's.
$null = $k32::FreeConsole()
if (-not $k32::AttachConsole(${childPid})) {
  # 6 = ERROR_INVALID_HANDLE, documented as "the specified process does
  # not have a console", so no console event could ever reach it.
  Write-Output ('no-console ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error())
  exit 0
}

# THE SAFETY CHECK. Group 0 means every process sharing this console, so
# firing into a console we share with the test runner would take the whole
# suite down with it. GetConsoleProcessList includes the caller, so the
# child and this PowerShell are the only two pids allowed to be here.
$buffer = [uint32[]]::new(64)
$count = $k32::GetConsoleProcessList($buffer, 64)
if ($count -eq 0 -or $count -gt 64) {
  Write-Output ('unreadable-console ' + $count)
  exit 0
}
$attached = @($buffer[0..($count - 1)])
$strangers = @($attached | Where-Object { $_ -ne ${childPid} -and $_ -ne $PID })
if ($strangers.Count -gt 0) {
  Write-Output ('shared-console ' + ($attached -join ','))
  exit 0
}

# Ignore the Ctrl+C we are about to raise, since we are in this console
# too. This must come after AttachConsole: attaching "will reset the table
# of control handlers in the client process to its initial state".
$null = $k32::SetConsoleCtrlHandler([IntPtr]::Zero, $true)
if ($k32::GenerateConsoleCtrlEvent(${CTRL_C_EVENT}, ${ALL_IN_THIS_CONSOLE})) {
  Write-Output 'sent'
} else {
  Write-Output ('failed ' + [Runtime.InteropServices.Marshal]::GetLastWin32Error())
}
`
}

/**
 * Deliver a real Ctrl-C to an already-running child.
 *
 * @param {import('node:child_process').ChildProcess} child
 * @returns {Promise<{ ok: true, reason?: undefined } | { ok: false, reason: string }>}
 *   `ok: false` means the OS would not let us generate the event, which is
 *   a property of the runner rather than of the code under test.
 *   (`reason?: undefined` on the success arm is not decoration: this repo
 *   typechecks with `strict: false`, and without `strictNullChecks` an
 *   `if (!result.ok)` does not narrow a discriminated union. Declaring the
 *   property on both arms keeps the natural call site typechecking.)
 */
async function interrupt (child) {
  if (!IS_WINDOWS) {
    child.kill('SIGINT')
    return { ok: true }
  }

  if (child.pid === undefined) return { ok: false, reason: 'the child has no pid to aim at' }

  /** @type {{ stdout: string, stderr: string } | { failed: string }} */
  const result = await new Promise((resolve) => {
    execFile(
      'powershell.exe',
      ['-NoProfile', '-NonInteractive', '-Command', ctrlCScript(child.pid)],
      { timeout: 20000 },
      (error, stdout, stderr) => {
        if (error) resolve({ failed: `powershell could not run it: ${error.message}${stderr.trim() ? ` -- ${stderr.trim()}` : ''}` })
        else resolve({ stdout, stderr })
      }
    )
  })

  if ('failed' in result) return { ok: false, reason: result.failed }

  const output = result.stdout.trim()
  if (output === 'sent') return { ok: true }

  // Every other branch is a measurement of this runner, so it is worth
  // saying which one happened rather than just "could not send".
  const [outcome, detail] = output.split(' ')
  const explained = /** @type {Record<string, string>} */ ({
    'no-console': `the child has no console, so no control event can reach it (AttachConsole error ${detail})`,
    'shared-console': `the child shares a console with the test runner (pids ${detail}), and firing into it would have killed the suite`,
    'unreadable-console': `GetConsoleProcessList returned ${detail}`,
    failed: `GenerateConsoleCtrlEvent failed with Win32 error ${detail}`
  })[outcome]

  return {
    ok: false,
    reason: explained ?? `unexpected helper output ${JSON.stringify(output)}${result.stderr.trim() ? ` (stderr: ${result.stderr.trim()})` : ''}`
  }
}

module.exports = { interrupt, IS_WINDOWS }

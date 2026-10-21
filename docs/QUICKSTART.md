# Quickstart

Adhal sends a file directly from one computer to another. The person
receiving gets a short code of five words. The person sending types that
code, and the file goes straight between the two machines, encrypted end
to end. There is no account to create and no upload site, and no server
keeps a copy.

This guide takes you from nothing installed to your first file sent. It
takes about five minutes. Both computers need the steps in "Install."

## What you need

- **macOS or Linux** on both computers. Windows is not supported yet.
- **Node.js 24 or newer** on both computers. Adhal is distributed through
  npm, the package manager that comes with Node.js.
- **An internet connection** on both computers. They do not need to be on
  the same network.

## Install

### 1. Check for Node.js

Open a terminal and run:

```bash
node -v
```

If it prints `v24` or higher (for example, `v24.19.0`), skip to step 2.
If it prints a lower version, or `command not found`, install the current
LTS release from [nodejs.org](https://nodejs.org/en/download), or with
your usual package manager:

```bash
brew install node          # macOS, with Homebrew
```

Then open a new terminal and run `node -v` again.

### 2. Install the Adhal CLI

```bash
npm install --global @ad-hal/cli
```

This gives you three commands:

| Command          | What it does                                      |
| ---------------- | ------------------------------------------------- |
| `ad-hal-receive` | waits for a file, and shows the code to share     |
| `ad-hal-send`    | sends a file to whoever is showing a code         |
| `ad-hal-code`    | prints a sample code and its QR symbol, nothing else |

To check the install, run:

```bash
ad-hal-receive --help
```

If you see `command not found`, npm's global `bin` directory is not on
your `PATH`. Run `npm prefix --global` to find it, and add its `bin`
subdirectory to your `PATH`.

Only `@ad-hal/cli` and `@ad-hal/engine` are official. Treat any other
package that calls itself Adhal as unofficial.

## Send your first file

The **receiver goes first**, because the receiver creates the code.

### On the receiving computer

Choose the folder the file should land in, and run:

```bash
ad-hal-receive - ~/Downloads
```

After a few seconds it prints a QR symbol and a line like this:

```
  scan the code above, or type:  duvet-outlast-slacked-squiggly-refrain
```

Give those five words to the sender, by reading them aloud, or by a
message only they will see. **Do it promptly**, because the receiver
waits 30 seconds for the sender to connect and then gives up. (If it
times out, run the command again for a fresh code.)

### On the sending computer

```bash
ad-hal-send - ./report.pdf
```

The `-` means "ask me for the code." At the `drop code:` prompt, type
the five words and press Enter. **What you type is not shown on screen**,
on purpose. Capital letters, and spaces instead of dashes, are both fine,
and if you mistype a word you are told which one before anything is sent.

### Back on the receiving computer

Before anything is saved, the receiver is shown what is on offer and
asked to accept it:

```
offer: "report.pdf" (2.4 MB, 2483112 bytes)
  sha256: 3f9a… (the sender's claim; the file is checked against it before it is saved)
accept this file? [y/N]
```

Type `y` and press Enter. Both sides show progress, and when the transfer
completes, each side prints the same `sha256:` line and a `verified:`
line. The receiver also prints where the file was saved:

```
[swarm-receive] verified: the file matches the sender's manifest digest
[swarm-receive] saved to: /Users/you/Downloads/report.pdf
```

Both commands then exit. The code is used up, so the next file needs a
new code.

## Good to know

- **Treat the code like a key.** Anyone who has it can take the file, so
  share it only with the person you mean to send to. If someone else got
  there first, both sides are told.
- **Adhal is not anonymous.** It hides the file, not the people: each side
  can see the other's IP address, and so can a few of the network nodes
  that help the two sides find each other. Both commands remind you of
  this when they start.
- **Nothing is overwritten.** If `report.pdf` already exists, the new file
  is saved as `report (1).pdf`. Pass `--replace` to overwrite instead.
- **Watch for warnings.** A file that could run something when opened (a
  program, a script, a disk image, or an archive, for example `.app`,
  `.sh`, `.dmg`, or `.zip`) is flagged before you accept.
- **To cancel**, press Ctrl-C on either side. The other side is told that
  the drop was canceled.
- **An interrupted transfer resumes.** Start a new drop for the same file,
  received into the same folder, and only the missing part is fetched.
  (This works for files, not for streams like the folder example below.)

## Sending a folder

Adhal sends one file at a time. To send a folder, pack it with `tar` and
stream it:

```bash
tar c photos | ad-hal-send duvet-outlast-slacked-squiggly-refrain - --name=photos.tar --code-on-argv
```

In this case stdin carries the folder, so it cannot also carry the code,
and the code goes on the command line. `--code-on-argv` says you accept
that the code will be in your shell history and visible to other users of
the machine while the drop runs. The receiver gets `photos.tar`, which
`tar xf photos.tar` unpacks. Expect a warning when accepting it: an
archive is flagged because it can hold anything. A stream's size is not
known in advance, so its SHA-256 is checked when it ends.

## When something goes wrong

**The receiver says `timed out after 30000ms waiting for a peer`.** The
sender did not connect in time. Check that both sides used the same five
words, then start over with a new code. On a slow network, you can give
the receiver longer, or wait indefinitely with `0`:

```bash
ADHAL_JOIN_TIMEOUT=0 ad-hal-receive ~/Downloads
```

**The receiver says `no terminal to ask on, so the offer is declined`.**
You started it in a script or with its input redirected, so there was no
one to answer `accept this file?`. Run it in a normal terminal, or add
`--yes` to accept without being asked.

**The QR symbol does not scan.** QR codes scan only as dark on light. If
your terminal has a dark background or drops colors, use the words
instead, or try `ADHAL_QR_WIDE=1` for terminals whose font draws the
symbol badly.

**`ad-hal-send` refuses a code on the command line.** This is
deliberate, to keep the code out of your shell history. Use `-` and type
the code at the prompt instead, or add `--code-on-argv` if you really
need it on the command line, as in "Sending a folder."

## Update or uninstall

```bash
npm install --global @ad-hal/cli@latest   # update
npm uninstall --global @ad-hal/cli        # uninstall
```

A version with a known security problem is marked deprecated on npm, so
installing it prints a warning. What changed in each version is in the
[release notes](https://github.com/khartig/adhal/releases).

## Next steps

- `ad-hal-receive --help` and `ad-hal-send --help` list every option.
- [`THREAT-MODEL.md`](THREAT-MODEL.md) explains exactly what Adhal
  protects and what it does not.
- To report a security problem, follow [`SECURITY.md`](../SECURITY.md),
  not a public issue.
- To work on Adhal itself, see [`SETUP.md`](SETUP.md).

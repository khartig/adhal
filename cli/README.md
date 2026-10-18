# @ad-hal/cli

The command-line tools for [Adhal](https://github.com/khartig/adhal): move
a file directly between two machines with a one-shot drop code. No
account, and no server holding the bytes.

This is the official way to install Adhal. The source is
[github.com/khartig/adhal](https://github.com/khartig/adhal), and the only
official npm packages are this one and
[`@ad-hal/engine`](https://www.npmjs.com/package/@ad-hal/engine). Treat
any other package that claims to be Adhal as unofficial.

## Install

Node.js ≥ 24, on macOS or Linux.

```bash
npm install --global @ad-hal/cli
```

## Use

The receiver generates the code and shows it, as words and as a QR
symbol, once it can be found:

```bash
# on the receiving machine
ad-hal-receive --new ~/Downloads

# on the sending machine: type the words at the prompt
ad-hal-send - ./report.pdf
```

The receiver is shown the file's name, size, and SHA-256, and is asked
before anything is written. `--help` on either command lists every flag.
`ad-hal-code` prints a fresh drop code and its QR symbol.

## Before you use it

- **The code is a bearer capability.** Whoever holds it can complete the
  drop, so hand it over by a route only the intended person sees.
- **Adhal is not anonymous.** Each side's IP address is visible to the
  other, and to the DHT nodes near the drop's topic.
- **Windows is not supported for security purposes** yet.
- **This is 0.x.** The wire protocol is frozen at v2, but the commands and
  their flags may still change.

Report a vulnerability through the repository's
[security policy](https://github.com/khartig/adhal/blob/main/SECURITY.md),
not in a public issue.

## License

MIT

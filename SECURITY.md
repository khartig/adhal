# Security policy

Ad-ḫal (Adhal, from the Sumerian *ad-ḫal*, "secret") moves a file between
two devices that share a one-shot code. If you have found a way to break
what it claims, this page says how to tell us and what happens next.

## Reporting a vulnerability

**Use GitHub's private vulnerability reporting:** on this repository's
**Security** tab, choose **Report a vulnerability**. That opens a private
advisory that only the maintainer can see. Please do not open a public
issue, pull request, or discussion for a vulnerability.

A useful report says:

- what you did, and on which commit or version;
- what you expected, and what happened instead;
- which claim it breaks, if it maps to one in
  [`docs/PROTOCOL.md`](docs/PROTOCOL.md) §12.2, or why it matters if it
  does not;
- a reproduction (a test, a script, or captured bytes), if you have one.

## What happens next

These are targets for a project maintained by one person, not
guarantees:

| | Within |
|---|---|
| Acknowledgment that the report arrived | 7 days |
| A first assessment: confirmed, not reproduced, or out of scope | 14 days |
| A fix, or an agreed plan for one, for a confirmed issue | 90 days |

Disclosure is coordinated: the advisory is published once a fix is
available, or when 90 days have passed, whichever comes first, unless we
agree on something else. You are credited in the advisory unless you ask
not to be.

## What is in scope

The claims in [`docs/PROTOCOL.md`](docs/PROTOCOL.md) §12.2 are the target.
Anything that breaks one of them is in scope, against the latest commit
on the default branch: the engine (`engine/src/`), the CLIs (`cli/src/`),
and the specification.

Some properties are **deliberately not claimed**, and §12.3 lists them.
Reports about them are welcome as discussion, but they are not
vulnerabilities in this sense:

- anonymity: both IP addresses are visible to the peer and to DHT nodes;
- anything a peer that holds the code can do within what the protocol
  lets the peer do, since the code is a bearer capability;
- denial of service, including burning a drop with 100 wrong guesses;
- a compromised endpoint, or memory that Node cannot erase;
- Windows, which is not supported for security purposes yet;
- the `scratch-*` diagnostics in `engine/`, which are not shipped.

## Official sources

Adhal comes from two places only:

- the repository, [github.com/khartig/adhal](https://github.com/khartig/adhal);
- the npm packages [`@ad-hal/cli`](https://www.npmjs.com/package/@ad-hal/cli),
  which is the one to install, and
  [`@ad-hal/engine`](https://www.npmjs.com/package/@ad-hal/engine), which
  the CLI depends on.

Neither package has been published yet. Any other package or repository
that claims to be Adhal is unofficial, including the unscoped npm names
`ad-hal`, `adhal`, and `ad-hal-cli`. If one of those turns up claiming
to be Adhal, please report it the way you would report a vulnerability.

## Supported versions

There are no releases yet. The wire format is v2, frozen at the tag
`v2-final` (W17, [`docs/IMPLEMENTATION-PLAN.md`](docs/IMPLEMENTATION-PLAN.md)).
Until the first release, only the default branch is supported.

## Status of earlier findings

An AI-assisted review of the v2 implementation found 21 issues. Each one
has a status in [`docs/SECURITY-REVIEW.md`](docs/SECURITY-REVIEW.md). That
review was not independent; an independent review of the cryptographic
composition is planned now that the wire format is frozen.

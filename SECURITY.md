# Security Policy

Fixes go to `main` and into the next release. Only the latest release is
supported.

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.** Use
GitHub's private vulnerability reporting instead: the **Security** tab of
this repository, then **Report a vulnerability**. Include:

1. A description of the vulnerability
2. Steps to reproduce it
3. The potential impact
4. Any suggested fix (optional)

## Scope

In scope: anything that lets a remote party crash the relay with crafted
packets, take over or disrupt a session it does not own, or learn more than
the SRT header already shows in clear text.

Known and by design (see the Security section of the README and
[Abuse protection](docs/DESIGN.md#abuse-protection)): the streamid is the
pairing key and there is no authentication, so whoever knows a streamid can
take or block that session (not read it, with a passphrase). Floods from
many networks, or with spoofed sources, can use up the global handshake
budget while they last (established sessions are not affected), and a
volume flood beyond what one thread can read affects every session.

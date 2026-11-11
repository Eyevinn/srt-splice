# Security Policy

This project is experimental and has no supported release yet. Fixes go to
`main`.

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

Known and by design (see the Security section of the README): the streamid
is the pairing key, and there is no authentication or rate limiting yet.

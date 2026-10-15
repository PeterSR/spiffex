# Security policy

spiffex is identity infrastructure, and security reports get priority.

## Reporting a vulnerability

Please report vulnerabilities **privately** through GitHub's private vulnerability reporting: the
**Security** tab of [PeterSR/spiffex](https://github.com/PeterSR/spiffex), then *Report a
vulnerability*. If that form is unavailable, use the contact options on the maintainer's
[GitHub profile](https://github.com/PeterSR) to arrange a private channel. Do not open a public
issue for anything you believe is a security problem.

You can expect an acknowledgement within a few days. A reproduction helps most: a request the issuer
should have refused, or a token a verifier should have rejected.

## Scope

In scope:

- the issuer: client assertion and token exchange verification, the mapping of proofs to SPIFFE IDs,
  signing key handling and rotation;
- the agent: the Workload API surface, token caching, bundle handling;
- the specification in [SPEC.md](SPEC.md).

Not spiffex vulnerabilities, by design (see SPEC.md sections 5 and 6):

- someone who can connect to an agent's socket receiving that workload's identity. The agent serves
  one workload; restricting access to its socket is the deployment's job.
- compromise of an upstream issuer you configured the issuer to trust for token exchange.
- missing transport encryption. Run the issuer behind TLS.

## Supported versions

Before 1.0, security fixes target the latest release only.

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

- the issuer: client assertion and token exchange verification, the mapping of proofs to SPIFFE IDs
  (admission, name templates, owner pinning for shared upstreams), fetching upstream keys, signing
  key handling and rotation;
- the state: validation, including the grant closure rule, and how each storage form is read and
  written;
- the management API: authentication, permission checks, and anything a caller can learn about
  objects it may not read;
- running exec verifiers: their isolation, deadlines and limits, what reaches them, and the startup
  check that keeps the signing keys from a `verifier_user`;
- the agent: the Workload API surface, token caching, bundle handling;
- the specification in [SPEC.md](SPEC.md).

Not spiffex vulnerabilities, by design (see SPEC.md section 10):

- someone who can connect to an agent's socket receiving that workload's identity, and its grants.
  The agent serves one workload; restricting access to its socket is the deployment's job.
- someone who can write the stored state, or who holds `write` on `/`, controlling every identity.
  Protect the storage like the signing keys and give that grant sparingly.
- a grant's `write` on a scope letting its holder take on the identities in that scope. That is
  what writing means; the closure rule only keeps it from reaching grants the writer does not hold.
- compromise of an upstream issuer you configured the issuer to trust, or someone allowed to obtain
  its tokens (for Kubernetes, to create service account tokens) taking on the identities it maps to.
- a flaw in an exec verifier you installed, such as one that does not check that a proof names its
  audience. Verifiers are part of the operator's deployment, though bugs in how the issuer runs
  them are in scope.
- an intercepted client assertion or management token being used once on each issuer process within
  its lifetime of at most five minutes, when processes share no replay record. The documentation
  says so.
- missing transport encryption. Run the issuer behind TLS.

## Supported versions

Before 1.0, security fixes target the latest release only.

# Security Policy

This repository is the Litecoin Dev Kit (LDK) fork of rust-bitcoin, published as
the `litecoin` crate, with Litecoin and MWEB support.

As a general rule, an issue is a security vulnerability if it could lead to:

* Loss of funds
* Loss of privacy
* Censorship (including e.g. by attaching an incorrectly low fee to a transaction)
* A client being unable to follow the chain (for example, rejecting data Litecoin Core accepts)
* Any "ordinary" security problem, such as remote code execution or invalid memory access

In general, use your best judgement in determining whether an issue is a security issue. If not,
go ahead and post it to the public issue tracker.

**If you believe you are aware of a security issue**, report it privately through GitHub:
<https://github.com/LitecoinDevKit/rust-litecoin/security/advisories/new>. Please do not open a
public issue for it.

If the issue is in code this fork inherits unchanged from rust-bitcoin, please also report it
upstream as described in
[rust-bitcoin's security policy](https://github.com/rust-bitcoin/rust-bitcoin/blob/master/SECURITY.md).

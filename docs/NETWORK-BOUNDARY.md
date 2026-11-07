# Outbound network policy — scope and test plan

This repository includes a **policy demonstration**, not an outbound network proxy. The `PolicyEngine.check_ssrf()` helper is a **fail-closed URL preflight only**: it rejects malformed destinations, private IP literals, non-HTTPS URLs and hosts that were not explicitly approved. It never opens a socket, resolves DNS, follows a redirect or verifies a TLS peer. A passing return value is **not evidence that the final destination is safe**.

## Necessary enforcement outside this helper

1. Supply exact hostnames through an operator-controlled allowlist. Do not accept destination lists supplied by models, retrieved documents or untrusted tool metadata.
2. Enforce network policies **at the transport / container / firewall layer**. Resolve each address, reject private, loopback, link-local and metadata addresses at connection time; protect against DNS changes between the check and connect.
3. Restrict redirects and revalidate every destination. Never follow an untrusted redirect to a new host using the original approval.
4. Keep outbound proxy and network credentials outside agent context. Use minimal egress privileges.
5. Test with synthetic URL payloads first and with a disposable, isolated integration environment before claiming live enforcement.

**Known limit:** `PolicyEngine` is not wired into Twinthos's commercial Hermes/Orgo runtime, and the stand-alone `check_ssrf` helper cannot block its network requests. This review does not establish production protection.

## Reproduce

```sh
python3 -m unittest tests.test_destination_policy -v
python3 -m unittest discover -s tests -v
```

Cases cover invalid schemes, URLs containing userinfo, hostname lookalikes, blocked subdomains, non-standard ports, private literals and missing allowlists. These are local deterministic tests, not live DNS-rebinding or egress tests.

Future integration must prove the actual HTTP transport enforces the same destination policy and cannot be bypassed via another tool, shell, browser, redirect or proxy.

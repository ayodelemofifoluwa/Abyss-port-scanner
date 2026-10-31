# Security Policy

## Responsible use

Abyss is a port-scanning tool. Only point it at hosts you own or have
explicit, documented permission to test. Unauthorized scanning of networks
you don't control may violate the law (e.g. the U.S. Computer Fraud and
Abuse Act, or equivalent legislation elsewhere) and the terms of service of
most ISPs and cloud providers.

`scanme.nmap.org` is maintained by the nmap project specifically as a safe,
always-permitted target for practicing scans of any kind.

## Reporting a vulnerability in Abyss itself

If you find a security issue in Abyss's own code (not in a target you scan
with it), please open a private security advisory on GitHub
(Security tab → "Report a vulnerability") rather than a public issue, so
there's time to fix it before details are public.

## Scope note

Abyss intentionally does not include automated credential brute-forcing,
a local vulnerability/CVE database, or packet capture. See the README's
"Scope, honestly" section for the reasoning. Feature requests in these
areas will likely be declined for the same reasons.

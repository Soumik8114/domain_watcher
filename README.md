## Install

```
pip install -r requirements.txt
```

## Use

```
python domain_watch.py acme.com
python domain_watch.py acme.com acmecorp.io
python domain_watch.py acme.com --min-score 30
python domain_watch.py acme.com --json results.json
```
A ranked terminal table:

```
Score  Real Domain   Fake Domain      Technique    Registrar        New Reg?
92     acme.com      acrne.com        homoglyph    NameSilo LLC     yes
61     acme.com      acme-login.com   subdomain    GoDaddy          yes
34     acme.com      acme.net         tld-swap     MarkMonitor      -
```

- **Score (0-100)**: how suspicious the domain looks — combines whether it's
  a very close typo, whether it was registered recently, and which
  technique produced it.
- **Technique**: how dnstwist derived the candidate (homoglyph, omission,
  transposition, tld-swap, subdomain, bitsquatting, etc.)
- **New Reg?**: registered in the last 90 days — a strong tell when paired
  with a brand-mimicking name.

Add `--json results.json` to also dump full details (DNS records, exact
registration date, etc.) for later review or reporting.

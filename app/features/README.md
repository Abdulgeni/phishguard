# Feature reference

All features are integers computed from the *normalized* URL (`normalize.py`): NFC, lowercase
host, non-ASCII labels IDNA-encoded, default ports and empty `?`/`#` removed, `http://` assumed
when the scheme is missing. Unknown numeric = `-1`, unknown boolean = `0`; no feature is ever
null. The feature set and order are frozen at Step 7; extra features need explicit approval.

`has_https` is deliberately **not** a feature (see Step 1, flaw 5): scheme-less dataset rows get
`http://` prepended identically at train and serve, so `has_https` is essentially constant in
training data. At serve time, real users send `https://` URLs, producing a value the tree almost
never sees. That makes it out-of-distribution input with undefined behavior and weak signal.

## Lexical (17): `lexical.py`, pure, no I/O

| Feature | Definition | Why it correlates with phishing | Sentinel |
|---|---|---|---|
| `url_length` | characters in the normalized URL | Long URLs hide the real host and carry encoded payloads. | n/a |
| `host_length` | characters in the host | Deceptive hosts pack in brand names and extra labels. | n/a |
| `path_length` | characters in the path | Long paths mimic login/redirect flows. | n/a |
| `num_dots` | `.` in the whole URL | Many dots indicate subdomain stacking. | n/a |
| `num_hyphens` | `-` in the whole URL | Hyphenated lookalikes (`paypal-secure-login`). | n/a |
| `num_digits` | digits in the whole URL | Generated hostnames and obfuscation use digits. | n/a |
| `num_slashes` | `/` in the whole URL (includes the two in `://`) | Deep or redirect-style paths. | n/a |
| `num_query_params` | non-empty `&`-separated query segments | Tracking or credential parameters. | n/a |
| `num_subdomains` | labels left of the registered domain (`www` counts) | `login.bank.evil.com` style spoofing. | `-1` (IP host, no public suffix, parser failure) |
| `has_ip_host` | host is an IPv4/IPv6 literal | Legitimate sites rarely use a raw IP. | n/a |
| `has_at_symbol` | `@` anywhere in the URL | `user@host` hides the true destination. | n/a |
| `has_punycode` | any host label starts with `xn--` | Punycode enables homograph attacks. | n/a |
| `tld_length` | characters in the public suffix (`co.uk` = 5) | Cheap or odd TLDs skew toward abuse. | `-1` (IP host, no public suffix, parser failure) |
| `path_depth` | non-empty `/`-separated path segments | Deeply nested paths imitate real sites. | n/a |
| `suspicious_keyword_hits` | distinct keywords from `data/suspicious_keywords.txt` found (case-insensitive substring) anywhere in the URL | Phishing URLs lean on `login`, `verify`, `secure`, `account`. | n/a |
| `has_double_slash_in_path` | `//` inside the path (not the query) | Classic redirect/obfuscation trick. | n/a |
| `has_hex_encoding` | any `%XX` with two hex digits | Percent-encoding obfuscates payloads and hosts. | n/a |

Public-suffix data comes from the snapshot bundled with `tldextract`; it is never fetched at
runtime. The keyword list is generic on purpose (no brand names): a brand token on the brand's own
domain is benign, and a lexical feature cannot tell the difference.

## Host (3): `host.py`, offline list + best-effort WHOIS

| Feature | Definition | Why it correlates with phishing | Sentinel |
|---|---|---|---|
| `domain_age_days` | whole days from the WHOIS creation date of the *registered domain* to now (via `Clock`) | Phishing domains are usually days or weeks old. | `-1` (WHOIS disabled, skipped, timed out, failed, empty record, IP host, no registered domain, missing or future creation date) |
| `is_shortener` | host equals or is a subdomain of an entry in `data/shorteners.txt` (static, no network) | Shorteners hide the real destination. | `0` (IP hosts are never shorteners) |
| `registrar_known` | WHOIS returned a non-empty registrar string | Missing registrar data is a mild abuse signal. | `0` |

### WHOIS behaviour

- Only the registered domain is queried (never the raw host), via `python-whois`, and only for
  non-IP hosts with a public suffix.
- The effective timeout is `min(WHOIS_TIMEOUT_SECONDS, remaining request budget)`; a remaining
  budget of 0 or less skips WHOIS entirely.
- A timed-out lookup cannot be killed. It keeps running in a daemon thread and keeps its slot
  (max 8 concurrent lookups); when it finishes, its result still warms the cache. When all slots
  are busy, new lookups are skipped rather than queued.
- Cache: LRU, 10,000 entries, keyed by registered domain. Successes live 24h; failures and
  timeouts live 10 min so dead domains are not hammered. Age is recomputed on every read.
- Concurrent lookups of the same uncached domain are not deduplicated.
- Every failure path returns sentinels and never raises. Failures log one `whois_failed`
  WARNING with a `reason` and the registered domain (never the full URL).

Result `status` (internal; `whois_skipped` is true for the last four of the first group):

| status | meaning | `whois_skipped` |
|---|---|---|
| `ok` | fresh lookup returned data | false |
| `cached` | answered from cache (may replay a recent failure) | false |
| `failed` | lookup raised or returned an empty record | false |
| `timeout` | lookup exceeded the effective timeout | true |
| `saturated` | all lookup slots busy | true |
| `budget_exhausted` | no request budget left | true |
| `disabled` | `WHOIS_DISABLED=true` | true |
| `not_applicable` | IP host or no registered domain | false |

### Train/serve skew (decision 4: read this)

At train time every row gets `domain_age_days = -1` and `registrar_known = 0`; only
`is_shortener` varies (from the static list). Because those two columns are constant in the
training data, the trees never split on them: **in this version the WHOIS features carry no
learned signal.** They are computed and echoed at serving time, but they do not change the
verdict. This is stated again in `model_card.json`.

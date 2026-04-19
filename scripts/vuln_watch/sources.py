"""Declarative list of sources polled by the daily vuln scan."""
from dataclasses import dataclass
from typing import Literal

Kind = Literal["rss", "atom", "html"]


@dataclass(frozen=True)
class Source:
    name: str
    url: str
    kind: Kind
    # For HTML sources: regexes used to extract advisory IDs from the page.
    advisory_id_patterns: tuple[str, ...] = ()
    # Human-facing URL to use as permalink fallback when `url` points at a
    # non-browsable endpoint (e.g. a JS data file). Empty = use `url`.
    display_url: str = ""
    # Per-source UA override. AMD's CDN drops connections when the UA string
    # contains a parenthesized URL, while Intel/ARM's WAF rejects UAs that
    # don't identify themselves — so we can't use one UA everywhere.
    # Empty = use the module-level USER_AGENT.
    user_agent: str = ""


SOURCES: tuple[Source, ...] = (
    Source("phoronix",       "https://www.phoronix.com/rss.php", "rss"),
    Source("oss-sec",        "https://seclists.org/rss/oss-sec.rss", "rss"),
    Source("lwn",            "https://lwn.net/headlines/newrss", "rss"),
    Source("project-zero",   "https://googleprojectzero.blogspot.com/feeds/posts/default", "atom"),
    Source("vusec",          "https://www.vusec.net/feed/", "rss"),
    Source("comsec-eth",     "https://comsec.ethz.ch/category/news/feed/", "rss"),
    # api.msrc.microsoft.com/update-guide/rss is the real RSS endpoint; the
    # msrc.microsoft.com/... URL returns the SPA shell (2.7 KB) instead.
    Source("msrc",           "https://api.msrc.microsoft.com/update-guide/rss", "rss"),
    Source("cisa",           "https://www.cisa.gov/cybersecurity-advisories/all.xml", "rss"),
    Source("cert-cc",        "https://www.kb.cert.org/vuls/atomfeed/", "atom"),
    Source("intel-psirt",    "https://www.intel.com/content/www/us/en/security-center/default.html", "html",
           (r"INTEL-SA-\d+",)),
    Source("amd-psirt",      "https://www.amd.com/en/resources/product-security.html", "html",
           (r"AMD-SB-\d+",),
           user_agent="spectre-meltdown-checker/vuln-watch"),
    Source("arm-spec",       "https://developer.arm.com/Arm%20Security%20Center/Speculative%20Processor%20Vulnerability", "html",
           (r"CVE-\d{4}-\d{4,7}",)),
    # transient.fail renders its attack table from tree.js client-side; we
    # pull the JS file directly (CVE regex works on its JSON-ish body).
    Source("transient-fail", "https://transient.fail/tree.js", "html",
           (r"CVE-\d{4}-\d{4,7}",),
           display_url="https://transient.fail/"),
)

# Identify ourselves honestly. Akamai/Cloudflare WAFs fronting intel.com,
# developer.arm.com, and cisa.gov return 403 when the UA claims "Mozilla"
# but TLS/HTTP fingerprint doesn't match a real browser — an honest bot UA
# passes those rules cleanly.
USER_AGENT = (
    "spectre-meltdown-checker/vuln-watch "
    "(+https://github.com/speed47/spectre-meltdown-checker)"
)
REQUEST_TIMEOUT = 30

from domainguard.modules.base import ScanContext
from domainguard.modules.spf_analysis import SpfAnalysisModule

from .helpers import FakeResolver, ok

D = "example.com"


def run(records):
    answers = {(name, "TXT"): ok(name, "TXT", rec) for name, rec in records.items()}
    ctx = ScanContext(domain=D, resolver=FakeResolver(answers))
    return {f.id for f in SpfAnalysisModule().run(ctx)}


def test_broad_ranges_inside_a_provider_include_are_not_flagged():
    ids = run({
        D: "v=spf1 include:spf.provider.net -all",
        "spf.provider.net": "v=spf1 ip4:40.92.0.0/15 ip4:52.100.0.0/15 -all",
    })
    assert ids == {"SPF-100"}


def test_broad_ranges_in_nested_includes_are_not_flagged():
    ids = run({
        D: "v=spf1 include:a.provider.net -all",
        "a.provider.net": "v=spf1 include:b.provider.net -all",
        "b.provider.net": "v=spf1 ip4:10.0.0.0/8 -all",
    })
    assert ids == {"SPF-100"}


def test_broad_range_in_the_domains_own_record_is_still_flagged():
    assert run({D: "v=spf1 ip4:10.0.0.0/8 -all"}) == {"SPF-014", "SPF-100"}
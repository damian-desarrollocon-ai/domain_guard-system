from domainguard.core.resolver import DnsAnswer


class FakeResolver:
    """Resolver simulado: sin red, respuestas definidas por la prueba."""

    def __init__(self, answers=None):
        self.answers = answers or {}
        self.calls = []

    def query(self, name, rdtype):
        self.calls.append((name, rdtype))
        key = (name.lower().rstrip("."), rdtype.upper())
        return self.answers.get(
            key, DnsAnswer(name=key[0], rdtype=key[1], status="no_data")
        )


def ok(name, rdtype, *records):
    return DnsAnswer(name=name, rdtype=rdtype, status="ok", records=list(records), ttl=300)


def status(name, rdtype, st):
    return DnsAnswer(name=name, rdtype=rdtype, status=st)
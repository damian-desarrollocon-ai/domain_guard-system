"""Acceso DNS centralizado: caché, timeouts y tope de consultas por escaneo."""
from __future__ import annotations

from typing import Literal, Protocol

import dns.exception
import dns.resolver
from pydantic import BaseModel, Field

QueryStatus = Literal["ok", "nxdomain", "no_data", "timeout", "servfail", "error"]


class DnsAnswer(BaseModel):
    name: str
    rdtype: str
    status: QueryStatus
    records: list[str] = Field(default_factory=list)
    ttl: int | None = None
    error: str | None = None

    @property
    def exists(self) -> bool:
        return self.status == "ok" and bool(self.records)


class QueryLimitExceeded(RuntimeError):
    """Se superó el máximo de consultas DNS permitido en un escaneo."""


class ResolverProtocol(Protocol):
    def query(self, name: str, rdtype: str) -> DnsAnswer: ...


class DnsResolver:
    def __init__(
        self,
        nameservers: list[str] | None = None,
        timeout: float = 3.0,
        lifetime: float = 6.0,
        max_queries: int = 200,
    ) -> None:
        self._resolver = dns.resolver.Resolver(configure=True)
        if nameservers:
            self._resolver.nameservers = list(nameservers)
        self._resolver.timeout = timeout
        self._resolver.lifetime = lifetime
        self._cache: dict[tuple[str, str], DnsAnswer] = {}
        self._max_queries = max_queries
        self.queries_made = 0

    @staticmethod
    def _format(rdata: object, rdtype: str) -> str:
        if rdtype == "TXT":
            return "".join(
                part.decode("utf-8", errors="replace") for part in rdata.strings  # type: ignore[attr-defined]
            )
        return rdata.to_text()  # type: ignore[attr-defined]

    def query(self, name: str, rdtype: str) -> DnsAnswer:
        qname = name.lower().rstrip(".")
        qtype = rdtype.upper()
        key = (qname, qtype)
        if key in self._cache:
            return self._cache[key]

        if self.queries_made >= self._max_queries:
            raise QueryLimitExceeded(
                f"Límite de {self._max_queries} consultas DNS alcanzado."
            )
        self.queries_made += 1

        try:
            answer = self._resolver.resolve(qname, qtype)
            result = DnsAnswer(
                name=qname,
                rdtype=qtype,
                status="ok",
                records=[self._format(r, qtype) for r in answer],
                ttl=answer.rrset.ttl if answer.rrset is not None else None,
            )
        except dns.resolver.NXDOMAIN:
            result = DnsAnswer(name=qname, rdtype=qtype, status="nxdomain")
        except dns.resolver.NoAnswer:
            result = DnsAnswer(name=qname, rdtype=qtype, status="no_data")
        except dns.exception.Timeout:
            result = DnsAnswer(name=qname, rdtype=qtype, status="timeout")
        except dns.resolver.NoNameservers:
            result = DnsAnswer(name=qname, rdtype=qtype, status="servfail")
        except dns.exception.DNSException as exc:
            result = DnsAnswer(name=qname, rdtype=qtype, status="error", error=str(exc))

        self._cache[key] = result
        return result
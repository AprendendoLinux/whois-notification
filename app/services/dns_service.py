"""Coleta de registros DNS e análise de segurança de e-mail (SPF/DMARC/DKIM)."""
import dns.exception
import dns.name
import dns.resolver

RECORD_TYPES = ["A", "AAAA", "NS", "MX", "TXT", "CAA", "SOA"]
DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "mail", "dkim", "s1", "s2"]


def _resolver() -> dns.resolver.Resolver:
    r = dns.resolver.Resolver()
    r.timeout = 3
    r.lifetime = 5
    return r


def _public_resolver() -> dns.resolver.Resolver:
    """Resolvers locais (ex.: systemd-resolved) costumam omitir registros DNSSEC."""
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
    r.timeout = 3
    r.lifetime = 6
    return r


def _query(r, name: str, rtype: str) -> list[str]:
    try:
        ans = r.resolve(name, rtype)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers,
            dns.exception.Timeout, dns.name.EmptyLabel):
        return []
    out = []
    for rd in ans:
        if rtype == "TXT":
            out.append(b"".join(rd.strings).decode(errors="replace"))
        elif rtype == "MX":
            out.append(f"{rd.preference} {str(rd.exchange).rstrip('.')}")
        elif rtype in ("NS", "CNAME"):
            out.append(str(rd.target).rstrip(".").lower())
        else:
            out.append(rd.to_text())
    return sorted(out)


def _analyze_spf(txt: list[str]) -> dict:
    spf = [t for t in txt if t.lower().startswith("v=spf1")]
    if not spf:
        return {"present": False, "record": None, "grade": "bad", "note": "Sem registro SPF"}
    if len(spf) > 1:
        return {"present": True, "record": " | ".join(spf), "grade": "bad",
                "note": "Mais de um registro SPF (inválido)"}
    rec = spf[0]
    if rec.rstrip().endswith("-all"):
        grade, note = "good", "Política estrita (-all)"
    elif rec.rstrip().endswith("~all"):
        grade, note = "ok", "Política branda (~all)"
    elif "+all" in rec:
        grade, note = "bad", "Permite qualquer remetente (+all)"
    else:
        grade, note = "ok", "Sem mecanismo 'all' explícito"
    return {"present": True, "record": rec, "grade": grade, "note": note}


def _analyze_dmarc(r, domain: str) -> dict:
    recs = [t for t in _query(r, f"_dmarc.{domain}", "TXT") if t.lower().startswith("v=dmarc1")]
    if not recs:
        return {"present": False, "record": None, "policy": None, "grade": "bad", "note": "Sem registro DMARC"}
    rec = recs[0]
    tags = {}
    for part in rec.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    policy = tags.get("p", "none").lower()
    grade = {"reject": "good", "quarantine": "ok"}.get(policy, "weak")
    note = {"reject": "Rejeita e-mails falsificados", "quarantine": "Envia falsificações para quarentena"}.get(
        policy, "Apenas monitora (p=none)")
    return {"present": True, "record": rec, "policy": policy, "grade": grade, "note": note}


def _analyze_dkim(r, domain: str) -> dict:
    found = []
    for sel in DKIM_SELECTORS:
        recs = _query(r, f"{sel}._domainkey.{domain}", "TXT")
        if any("p=" in t for t in recs):
            found.append(sel)
    return {
        "present": bool(found),
        "selectors": found,
        "grade": "good" if found else "unknown",
        "note": f"Seletores encontrados: {', '.join(found)}" if found
        else "Nenhum seletor comum encontrado (pode usar um seletor personalizado)",
    }


def email_score(spf: dict, dmarc: dict, dkim: dict, has_mx: bool) -> int:
    """Pontuação 0–100 da proteção contra falsificação de e-mail."""
    pts = {"good": 1.0, "ok": 0.7, "weak": 0.35, "unknown": 0.5, "bad": 0.0}
    score = 40 * pts[spf["grade"]] + 40 * pts[dmarc["grade"]] + 20 * pts[dkim["grade"]]
    if not has_mx and spf["grade"] == "good" and dmarc["grade"] == "good":
        score = 100
    return round(score)


def lookup(domain: str) -> dict:
    r = _resolver()
    records = {t: _query(r, domain, t) for t in RECORD_TYPES}
    if not any(records[t] for t in ("A", "AAAA", "NS", "MX", "SOA")):
        raise LookupError("o domínio não resolve (sem registros A, AAAA, NS, MX ou SOA)")
    www = _query(r, f"www.{domain}", "CNAME") or _query(r, f"www.{domain}", "A")

    dnssec = bool(_query(_public_resolver(), domain, "DS")) or bool(_query(r, domain, "DS"))
    spf = _analyze_spf(records["TXT"])
    dmarc = _analyze_dmarc(r, domain)
    dkim = _analyze_dkim(r, domain)
    caa = records["CAA"]

    return {
        "records": records,
        "www": www,
        "dnssec_signed": dnssec,
        "email": {
            "spf": spf,
            "dmarc": dmarc,
            "dkim": dkim,
            "score": email_score(spf, dmarc, dkim, bool(records["MX"])),
        },
        "caa_present": bool(caa),
    }

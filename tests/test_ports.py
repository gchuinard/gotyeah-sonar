"""Scan de ports : logique CDN, sélection de ports, codes — seams mockés, hors-ligne."""
from types import SimpleNamespace

import scanner.checks.ports as portsmod
from scanner.checks.ports import ports
from scanner.finding import Severity


def _ctx(host="x.com"):
    return SimpleNamespace(host=host)


def test_is_cdn_ip():
    assert portsmod._is_cdn_ip("104.16.0.1") == "Cloudflare"   # plage Cloudflare
    assert portsmod._is_cdn_ip("93.184.216.34") is None         # IP publique, hors CDN
    assert portsmod._is_cdn_ip("pas-une-ip") is None


def test_port_list_override(monkeypatch):
    monkeypatch.setenv("SONAR_PORTS_LIST", "6379, 22")
    assert {p for p, _s, _sev in portsmod._port_list()} == {6379, 22}


async def test_off(monkeypatch):
    monkeypatch.setenv("SONAR_PORTS", "off")
    out = await ports(_ctx())
    assert out[0].code == "off" and out[0].severity == Severity.INFO


async def test_behind_cdn(monkeypatch):
    monkeypatch.delenv("SONAR_PORTS", raising=False)
    monkeypatch.delenv("SONAR_ORIGIN_IP", raising=False)

    async def fake_resolve(host):
        return ["104.16.0.1"]
    monkeypatch.setattr(portsmod, "_resolve_ips", fake_resolve)
    out = await ports(_ctx())
    assert len(out) == 1 and out[0].code == "behind-cdn"
    assert out[0].params["cdn"] == "Cloudflare"


async def test_service_exposed(monkeypatch):
    monkeypatch.delenv("SONAR_PORTS", raising=False)
    monkeypatch.delenv("SONAR_ORIGIN_IP", raising=False)

    async def fake_resolve(host):
        return ["93.184.216.34"]

    async def fake_probe(ip, port, timeout):
        return (port == 6379, "")
    monkeypatch.setattr(portsmod, "_resolve_ips", fake_resolve)
    monkeypatch.setattr(portsmod, "_probe_port", fake_probe)
    out = await ports(_ctx())
    exposed = [f for f in out if f.code == "service-exposed"]
    assert len(exposed) == 1 and exposed[0].severity == Severity.CRITICAL
    assert exposed[0].params["service"] == "Redis" and exposed[0].params["port"] == 6379


async def test_clean(monkeypatch):
    monkeypatch.delenv("SONAR_PORTS", raising=False)
    monkeypatch.delenv("SONAR_ORIGIN_IP", raising=False)

    async def fake_resolve(host):
        return ["93.184.216.34"]

    async def fake_probe(ip, port, timeout):
        return (False, "")
    monkeypatch.setattr(portsmod, "_resolve_ips", fake_resolve)
    monkeypatch.setattr(portsmod, "_probe_port", fake_probe)
    out = await ports(_ctx())
    assert len(out) == 1 and out[0].code == "clean" and out[0].severity == Severity.PASS


async def test_scans_all_non_cdn_ips(monkeypatch):
    # Host multi-A mixte : 1 IP Cloudflare (ignorée) + 2 origines ; Redis ouvert sur la
    # SECONDE origine seulement → doit être trouvé (avant, seule ips[0] était scannée).
    monkeypatch.delenv("SONAR_PORTS", raising=False)
    monkeypatch.delenv("SONAR_ORIGIN_IP", raising=False)

    async def fake_resolve(host):
        return ["104.16.0.1", "93.184.216.34", "8.8.8.8"]

    async def fake_probe(ip, port, timeout):
        return (ip == "8.8.8.8" and port == 6379, "")
    monkeypatch.setattr(portsmod, "_resolve_ips", fake_resolve)
    monkeypatch.setattr(portsmod, "_probe_port", fake_probe)
    out = await ports(_ctx())
    exposed = [f for f in out if f.code == "service-exposed"]
    assert len(exposed) == 1
    assert exposed[0].params["ip"] == "8.8.8.8" and exposed[0].params["port"] == 6379


async def test_blocked_internal_no_probe(monkeypatch):
    # SSRF : un domaine vérifié repointé vers une IP interne → scan REFUSÉ, aucun probe.
    monkeypatch.delenv("SONAR_PORTS", raising=False)
    monkeypatch.delenv("SONAR_ORIGIN_IP", raising=False)
    monkeypatch.delenv("SONAR_ALLOW_PRIVATE", raising=False)

    async def fake_resolve(host):
        return ["192.168.1.42"]
    probed = []

    async def fake_probe(ip, port, timeout):
        probed.append(ip)
        return (False, "")
    monkeypatch.setattr(portsmod, "_resolve_ips", fake_resolve)
    monkeypatch.setattr(portsmod, "_probe_port", fake_probe)
    out = await ports(_ctx())
    assert len(out) == 1 and out[0].code == "blocked-internal"
    assert probed == []                                    # rien n'a été port-scanné


async def test_mixed_internal_scans_only_public(monkeypatch):
    # Host résolvant en [public, interne] → on ne sonde QUE la publique (jamais l'interne).
    monkeypatch.delenv("SONAR_PORTS", raising=False)
    monkeypatch.delenv("SONAR_ORIGIN_IP", raising=False)
    monkeypatch.delenv("SONAR_ALLOW_PRIVATE", raising=False)

    async def fake_resolve(host):
        return ["93.184.216.34", "127.0.0.1"]
    probed = set()

    async def fake_probe(ip, port, timeout):
        probed.add(ip)
        return (False, "")
    monkeypatch.setattr(portsmod, "_resolve_ips", fake_resolve)
    monkeypatch.setattr(portsmod, "_probe_port", fake_probe)
    await ports(_ctx())
    assert "127.0.0.1" not in probed and "93.184.216.34" in probed


async def test_allow_private_scans_internal(monkeypatch):
    # En homelab (SONAR_ALLOW_PRIVATE=on), on PEUT scanner une IP interne explicitement.
    monkeypatch.delenv("SONAR_PORTS", raising=False)
    monkeypatch.delenv("SONAR_ORIGIN_IP", raising=False)
    monkeypatch.setenv("SONAR_ALLOW_PRIVATE", "on")

    async def fake_resolve(host):
        return ["192.168.1.42"]

    async def fake_probe(ip, port, timeout):
        return (ip == "192.168.1.42" and port == 6379, "")
    monkeypatch.setattr(portsmod, "_resolve_ips", fake_resolve)
    monkeypatch.setattr(portsmod, "_probe_port", fake_probe)
    out = await ports(_ctx())
    exposed = [f for f in out if f.code == "service-exposed"]
    assert exposed and exposed[0].params["ip"] == "192.168.1.42"


async def test_origin_ip_bypasses_cdn(monkeypatch):
    monkeypatch.delenv("SONAR_PORTS", raising=False)
    monkeypatch.setenv("SONAR_ORIGIN_IP", "1.1.1.1")   # court-circuite résolution + CDN

    async def fake_probe(ip, port, timeout):
        return (ip == "1.1.1.1" and port == 3306, "")
    monkeypatch.setattr(portsmod, "_probe_port", fake_probe)
    out = await ports(_ctx())
    exposed = [f for f in out if f.code == "service-exposed"]
    assert exposed and exposed[0].params["port"] == 3306 and exposed[0].params["ip"] == "1.1.1.1"

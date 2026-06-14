"""Garde réseau anti-SSRF partagée (`scanner.netguard`)."""
import scanner.netguard as ng


def test_is_blocked_ip():
    for ip in ("127.0.0.1", "10.0.0.1", "192.168.1.1", "169.254.169.254", "::1", "0.0.0.0"):
        assert ng.is_blocked_ip(ip), ip
    for ip in ("8.8.8.8", "1.1.1.1", "93.184.216.34"):
        assert not ng.is_blocked_ip(ip), ip
    assert not ng.is_blocked_ip("pas-une-ip")


def test_host_is_internal_blocks_mixed(monkeypatch):
    # #2 : un hôte à résolution MIXTE (public + interne) est interne → `any`, pas `all`
    # (sinon il contournait la garde et exposait la ressource interne).
    monkeypatch.setattr(ng, "resolve_ips", lambda h: ["1.2.3.4", "127.0.0.1"])
    assert ng.host_is_internal("mixte.example") is True
    monkeypatch.setattr(ng, "resolve_ips", lambda h: ["1.2.3.4", "8.8.8.8"])
    assert ng.host_is_internal("public.example") is False
    monkeypatch.setattr(ng, "resolve_ips", lambda h: [])
    assert ng.host_is_internal("irresolu.example") is False   # irrésoluble → pas notre rôle


def test_allow_private(monkeypatch):
    monkeypatch.delenv("SONAR_ALLOW_PRIVATE", raising=False)
    assert ng.allow_private() is False
    monkeypatch.setenv("SONAR_ALLOW_PRIVATE", "on")
    assert ng.allow_private() is True
    monkeypatch.setenv("SONAR_ALLOW_PRIVATE", "off")
    assert ng.allow_private() is False

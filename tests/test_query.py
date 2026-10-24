import pytest

from aksec.query import QueryError, compile_query


def test_empty_query_matches_all():
    c = compile_query("")
    assert c.where == "1=1"
    assert c.params == []


def test_port_and_service():
    c = compile_query("port:443 service:HTTPS")
    assert "port = ?" in c.where
    assert "service = ?" in c.where
    assert 443 in c.params
    assert "https" in c.params  # service is lower-cased


def test_port_range():
    c = compile_query("port:8000-8100")
    assert "BETWEEN" in c.where
    assert c.params == [8000, 8100]


def test_cidr_uses_membership_function():
    c = compile_query("ip:10.0.0.0/8")
    assert "ip_in_cidr(ip, ?)" in c.where
    assert c.params == ["10.0.0.0/8"]


def test_ipv6_single_and_cidr():
    c = compile_query("ip:2001:db8::1")
    assert "ip = ?" in c.where
    assert c.params == ["2001:db8::1"]
    c2 = compile_query("ip:2001:db8::/32")
    assert "ip_in_cidr(ip, ?)" in c2.where
    assert c2.params == ["2001:db8::/32"]


def test_free_text_uses_fts():
    c = compile_query("nginx openssh")
    assert "service_fts MATCH ?" in c.where
    assert c.params == ['"nginx" "openssh"']


def test_unknown_field_rejected():
    with pytest.raises(QueryError):
        compile_query("frobnicate:1")


def test_invalid_port_rejected():
    with pytest.raises(QueryError):
        compile_query("port:99999")


def test_has_field():
    c = compile_query("has:tls")
    assert "json_extract" in c.where
    assert c.params == ["tls"]

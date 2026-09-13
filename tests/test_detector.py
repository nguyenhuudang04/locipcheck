"""
tests/test_detector.py — Unit tests for IOC type detection.
No network calls are made.
"""
import pytest
from src.detector import detect
from src.models import IOCType


class TestIPv4Detection:
    def test_valid_ipv4(self):
        assert detect("185.220.101.5") == IOCType.IPV4

    def test_loopback(self):
        assert detect("127.0.0.1") == IOCType.IPV4

    def test_private_ip(self):
        assert detect("192.168.1.100") == IOCType.IPV4

    def test_broadcast(self):
        assert detect("255.255.255.255") == IOCType.IPV4


class TestIPv6Detection:
    def test_full_ipv6(self):
        assert detect("2001:0db8:85a3:0000:0000:8a2e:0370:7334") == IOCType.IPV6

    def test_compressed_ipv6(self):
        assert detect("2001:db8::1") == IOCType.IPV6

    def test_loopback_ipv6(self):
        assert detect("::1") == IOCType.IPV6


class TestDomainDetection:
    def test_simple_domain(self):
        assert detect("malware.example.com") == IOCType.DOMAIN

    def test_two_label_domain(self):
        assert detect("evil.ru") == IOCType.DOMAIN

    def test_subdomain(self):
        assert detect("c2.attacker.net") == IOCType.DOMAIN


class TestURLDetection:
    def test_http_url(self):
        assert detect("http://phishing.site/login") == IOCType.URL

    def test_https_url(self):
        assert detect("https://evil.com/malware.exe") == IOCType.URL

    def test_url_with_query(self):
        assert detect("https://example.com/path?q=1") == IOCType.URL


class TestHashDetection:
    def test_md5(self):
        assert detect("d41d8cd98f00b204e9800998ecf8427e") == IOCType.MD5

    def test_sha1(self):
        assert detect("da39a3ee5e6b4b0d3255bfef95601890afd80709") == IOCType.SHA1

    def test_sha256(self):
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert detect(sha256) == IOCType.SHA256

    def test_uppercase_hash(self):
        assert detect("D41D8CD98F00B204E9800998ECF8427E") == IOCType.MD5


class TestEdgeCases:
    def test_empty_string(self):
        assert detect("") == IOCType.UNKNOWN

    def test_random_string(self):
        assert detect("not-an-ioc-!!!") == IOCType.UNKNOWN

    def test_partial_ip(self):
        assert detect("192.168.1") == IOCType.UNKNOWN

    def test_whitespace_stripped(self):
        assert detect("  8.8.8.8  ") == IOCType.IPV4

    def test_too_short_hash(self):
        # 31 chars — not MD5
        assert detect("d41d8cd98f00b204e9800998ecf842") == IOCType.UNKNOWN

"""Tests de syffer.utils.validation."""

from __future__ import annotations

import pytest

from syffer.utils.validation import (
    safe_filename,
    validate_bpf,
    validate_cidr,
    validate_ip,
)


class TestSafeFilename:
    def test_accepts_simple_name(self):
        assert safe_filename("rapport") == "rapport"

    def test_accepts_alphanumeric_dots_underscores_dashes(self):
        assert safe_filename("mon-rapport_2026.01") == "mon-rapport_2026.01"

    def test_rejects_empty(self):
        with pytest.raises(ValueError):
            safe_filename("")

    def test_rejects_whitespace_only(self):
        with pytest.raises(ValueError):
            safe_filename("   ")

    def test_rejects_parent_traversal(self):
        with pytest.raises(ValueError):
            safe_filename("../etc/passwd")

    def test_rejects_backslash(self):
        with pytest.raises(ValueError):
            safe_filename("foo\\bar")

    def test_rejects_forward_slash(self):
        with pytest.raises(ValueError):
            safe_filename("foo/bar")

    def test_rejects_too_long(self):
        with pytest.raises(ValueError):
            safe_filename("a" * 101)

    def test_strips_unsafe_chars(self):
        assert safe_filename("rapport!") == "rapport"


class TestValidateCidr:
    def test_accepts_valid_cidr(self):
        assert validate_cidr("192.168.1.0/24") == "192.168.1.0/24"

    def test_accepts_non_strict(self):
        assert validate_cidr("192.168.1.5/24") == "192.168.1.0/24"

    def test_accepts_single_host(self):
        assert validate_cidr("10.0.0.1/32") == "10.0.0.1/32"

    def test_rejects_invalid(self):
        with pytest.raises(ValueError):
            validate_cidr("not-a-cidr")

    def test_rejects_bad_prefix(self):
        with pytest.raises(ValueError):
            validate_cidr("192.168.1.0/33")


class TestValidateIp:
    def test_accepts_ipv4(self):
        assert validate_ip("8.8.8.8") == "8.8.8.8"

    def test_accepts_ipv6(self):
        assert validate_ip("::1") == "::1"

    def test_rejects_invalid(self):
        with pytest.raises(ValueError):
            validate_ip("999.999.999.999")

    def test_rejects_empty(self):
        with pytest.raises(ValueError):
            validate_ip("")


class TestValidateBpf:
    def test_accepts_simple(self):
        assert validate_bpf("tcp port 443") == "tcp port 443"

    def test_accepts_complex(self):
        assert validate_bpf("tcp and (port 80 or port 443)") == "tcp and (port 80 or port 443)"

    def test_rejects_empty(self):
        with pytest.raises(ValueError):
            validate_bpf("")

    def test_rejects_backtick(self):
        with pytest.raises(ValueError):
            validate_bpf("tcp `whoami`")

    def test_rejects_semicolon(self):
        with pytest.raises(ValueError):
            validate_bpf("tcp; rm -rf /")

    def test_rejects_pipe(self):
        with pytest.raises(ValueError):
            validate_bpf("tcp | cat /etc/passwd")

    def test_rejects_newline(self):
        with pytest.raises(ValueError):
            validate_bpf("tcp\nrm -rf /")

    def test_rejects_too_long(self):
        with pytest.raises(ValueError):
            validate_bpf("a" * 201)

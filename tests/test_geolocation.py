"""Tests de syffer.core.geolocation."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest
import requests

from syffer.core.geolocation import GeolocationError, lookup


def test_lookup_success(mocker):
    fake_response = MagicMock()
    fake_response.status_code = 200
    fake_response.json.return_value = {
        "status": "success",
        "country": "France",
        "city": "Paris",
        "regionName": "Ile-de-France",
        "lat": 48.8566,
        "lon": 2.3522,
        "isp": "TestISP",
    }
    mocker.patch("requests.get", return_value=fake_response)

    info = lookup("8.8.8.8")
    assert info.country == "France"
    assert info.city == "Paris"
    assert info.region == "Ile-de-France"
    assert info.lat == 48.8566
    assert info.lon == 2.3522
    assert info.isp == "TestISP"
    assert info.status == "success"


def test_lookup_rejects_invalid_ip():
    with pytest.raises(ValueError):
        lookup("not-an-ip")


def test_lookup_fail_status(mocker):
    fake_response = MagicMock()
    fake_response.status_code = 200
    fake_response.json.return_value = {"status": "fail", "message": "reserved range"}
    mocker.patch("requests.get", return_value=fake_response)

    with pytest.raises(GeolocationError):
        lookup("127.0.0.1")


def test_lookup_http_error(mocker):
    fake_response = MagicMock()
    fake_response.status_code = 500
    mocker.patch("requests.get", return_value=fake_response)

    with pytest.raises(GeolocationError):
        lookup("8.8.8.8")


def test_lookup_timeout(mocker):
    mocker.patch("requests.get", side_effect=requests.Timeout())
    with pytest.raises(GeolocationError):
        lookup("8.8.8.8", timeout=1)

"""Geolocalisation d'IP publique via ip-api.com."""

from __future__ import annotations

import logging

import requests

from syffer import config
from syffer.core.models import GeoInfo
from syffer.utils.validation import validate_ip

logger = logging.getLogger(__name__)


class GeolocationError(Exception):
    """Echec du lookup de geolocalisation."""


def lookup(ip: str, timeout: int | None = None) -> GeoInfo:
    """Interroge ip-api.com et renvoie un GeoInfo. Leve GeolocationError."""
    normalized = validate_ip(ip)
    timeout = timeout if timeout is not None else config.DEFAULT_HTTP_TIMEOUT
    url = config.IP_API_URL.format(ip=normalized)
    logger.debug("geolocation lookup : %s", url)

    try:
        response = requests.get(url, timeout=timeout)
    except requests.RequestException as exc:
        raise GeolocationError(f"echec HTTP : {exc}") from exc

    if response.status_code != 200:
        raise GeolocationError(f"HTTP {response.status_code}")

    payload = response.json()
    status = payload.get("status", "unknown")
    if status != "success":
        raise GeolocationError(f"reponse fail : {payload.get('message', 'inconnue')}")

    return GeoInfo(
        ip=normalized,
        country=payload.get("country"),
        city=payload.get("city"),
        region=payload.get("regionName"),
        lat=payload.get("lat"),
        lon=payload.get("lon"),
        isp=payload.get("isp"),
        status=status,
    )

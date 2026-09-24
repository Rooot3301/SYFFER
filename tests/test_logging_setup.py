"""Tests de syffer.utils.logging_setup."""

from __future__ import annotations

import logging

from syffer.utils.logging_setup import configure


def test_configure_sets_info_by_default():
    configure(verbose=False)
    assert logging.getLogger().level == logging.INFO


def test_configure_verbose_sets_debug():
    configure(verbose=True)
    assert logging.getLogger().level == logging.DEBUG


def test_configure_is_idempotent():
    configure(verbose=False)
    before = len(logging.getLogger().handlers)
    configure(verbose=False)
    after = len(logging.getLogger().handlers)
    assert before == after

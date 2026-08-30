from __future__ import annotations

from pathlib import Path

import pytest

from scripts.verify_outbound_http_inventory import (
    EXPECTED_FACTORY_CALLS,
    scan_production_tree,
    scan_source,
)

ROOT = Path(__file__).resolve().parents[1]


def test_production_outbound_inventory_is_exact_and_has_no_unapproved_calls():
    report = scan_production_tree(ROOT)

    assert report.findings == []
    assert report.factory_calls == EXPECTED_FACTORY_CALLS


@pytest.mark.parametrize(
    ("source", "expected_symbol"),
    [
        ("import httpx\nhttpx.AsyncClient()\n", "httpx.AsyncClient"),
        ("import httpx\nhttpx.get('https://example.com')\n", "httpx.get"),
        (
            "from urllib import request\nrequest.urlopen('https://example.com')\n",
            "urllib.request.urlopen",
        ),
        ("import requests as r\nr.get('https://example.com')\n", "requests.get"),
        (
            "from aiohttp import ClientSession as CS\nCS()\n",
            "aiohttp.ClientSession",
        ),
        (
            "import socket as s\ns.create_connection(('example.com', 443))\n",
            "socket.create_connection",
        ),
        (
            "import subprocess\nsubprocess.run(['curl', 'https://example.com'])\n",
            "subprocess.run",
        ),
        ("from openai import OpenAI\nOpenAI()\n", "openai.OpenAI"),
        ("import groq as g\ng.Groq()\n", "groq.Groq"),
    ],
)
def test_inventory_contract_catches_forbidden_bypass_mutations(source, expected_symbol):
    findings = scan_source(source, "core/mutated_runtime.py")

    assert any(finding.symbol == expected_symbol for finding in findings)


def test_inventory_contract_resolves_aliases_instead_of_string_matching():
    source = """
from httpx import AsyncClient as InnocentLookingName

def send():
    return InnocentLookingName()
"""

    findings = scan_source(source, "core/aliased_runtime.py")

    assert [finding.symbol for finding in findings if finding.kind == "call"] == [
        "httpx.AsyncClient"
    ]

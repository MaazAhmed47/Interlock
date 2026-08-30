"""AST-based regression contract for production server-side egress creation.

This is a source-inventory tripwire, not connection-time or network enforcement.
"""

from __future__ import annotations

import argparse
import ast
import json
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable

PRODUCTION_PATHS = ("core", "routes", "models", "proxy.py", "config.py")

EXPECTED_FACTORY_CALLS: dict[str, int] = {
    "core/admin.py::_GuardedPyJWKClient.fetch_data:create_sync_client": 1,
    "core/effect_readback.py::_call_upstream_tool:create_async_client": 1,
    "core/effective_permission.py::_call_upstream_for_observation:create_async_client": 1,
    "core/ema_auth.py::TrustedJWKSCache._refresh:create_async_client": 1,
    "core/llm_judge.py::_build_groq_client:create_sync_client": 1,
    "core/mcp_gateway.py::_fetch_tool_list_payload:create_async_client": 1,
    "core/mcp_gateway.py::proxy_mcp_tool_call:create_async_client": 1,
    "core/router.py::forward_to_provider:create_async_client": 1,
    "core/shadow_scanner.py::probe_target:create_async_client": 1,
    "core/siem.py::send_to_siem:create_async_client": 6,
    "core/webhook.py::fire_webhook:create_async_client": 1,
}

APPROVED_IMPORTS: dict[tuple[str, str], str] = {
    ("core/outbound_http.py", "httpx"): "central sync/async HTTP client factory",
    ("core/admin.py", "httpx"): "HTTP exception types and OIDC response handling",
    ("core/effect_readback.py", "httpx"): "HTTP exception types",
    ("core/effective_permission.py", "httpx"): "HTTP exception types",
    ("core/ema_auth.py", "httpx"): "HTTP types and bounded streaming response handling",
    ("core/mcp_gateway.py", "httpx"): "HTTP exception and response types",
    ("core/shadow_scanner.py", "httpx"): "HTTP types and exception classes",
    ("core/siem.py", "httpx"): "HTTP exception classes",
    ("core/url_security.py", "httpx"): "URL parsing only; no client construction",
    ("core/webhook.py", "httpx"): "HTTP exception classes",
    ("core/llm_judge.py", "groq"): "Groq SDK receives a factory-created HTTPX client",
    (
        "core/url_security.py",
        "socket",
    ): "Phase 1 DNS classification via getaddrinfo only",
    (
        "core/detection_quality_evidence.py",
        "subprocess",
    ): "local git revision/diff evidence; no network client",
}

APPROVED_DIRECT_CALLS: dict[tuple[str, str, str], tuple[int, str]] = {
    (
        "core/outbound_http.py",
        "create_sync_client",
        "httpx.Client",
    ): (1, "sole approved sync HTTPX construction"),
    (
        "core/outbound_http.py",
        "create_async_client",
        "httpx.AsyncClient",
    ): (1, "sole approved async HTTPX construction"),
    (
        "core/llm_judge.py",
        "_build_groq_client",
        "groq.Groq",
    ): (1, "SDK adapter supplied with the controlled sync HTTPX client"),
    (
        "core/detection_quality_evidence.py",
        "_git_revision_identity",
        "subprocess.run",
    ): (2, "bounded local git metadata commands only"),
}

NON_HTTP_INFRASTRUCTURE = {
    "core/db.py": "PostgreSQL/SQLite database transport; not routed through HTTP proxy",
    "core/rate_limit.py": "Redis rate-limit transport; not routed through HTTP proxy",
    "core/url_security.py": "DNS resolver used by the retained Phase 1 URL guard",
}

NON_RUNTIME_EGRESS_SCOPE = {
    "demo/": "offline/live proof programs include urllib, sockets, and subprocess clients",
    "examples/": "operator-side integration examples include HTTP and subprocess clients",
    "scripts/": "CI/operator tools may perform their own bounded egress",
}

FORBIDDEN_IMPORT_ROOTS = {
    "httpx",
    "urllib.request",
    "requests",
    "aiohttp",
    "http.client",
    "urllib3",
    "socket",
    "subprocess",
    "groq",
    "openai",
    "anthropic",
    "boto3",
    "botocore",
    "dns.resolver",
    "websockets",
}

FORBIDDEN_CALLS = {
    "httpx.Client",
    "httpx.AsyncClient",
    "httpx.get",
    "httpx.post",
    "httpx.put",
    "httpx.patch",
    "httpx.delete",
    "httpx.head",
    "httpx.options",
    "httpx.request",
    "httpx.stream",
    "urllib.request.urlopen",
    "urllib.request.build_opener",
    "requests.get",
    "requests.post",
    "requests.put",
    "requests.patch",
    "requests.delete",
    "requests.head",
    "requests.options",
    "requests.request",
    "requests.Session",
    "aiohttp.ClientSession",
    "http.client.HTTPConnection",
    "http.client.HTTPSConnection",
    "urllib3.PoolManager",
    "urllib3.ProxyManager",
    "socket.socket",
    "socket.create_connection",
    "asyncio.open_connection",
    "subprocess.run",
    "subprocess.Popen",
    "asyncio.create_subprocess_exec",
    "asyncio.create_subprocess_shell",
    "os.popen",
    "os.system",
    "groq.Groq",
    "groq.AsyncGroq",
    "openai.OpenAI",
    "openai.AsyncOpenAI",
    "anthropic.Anthropic",
    "anthropic.AsyncAnthropic",
    "boto3.client",
    "boto3.resource",
    "websockets.connect",
}


@dataclass(frozen=True, order=True)
class Finding:
    path: str
    line: int
    context: str
    symbol: str
    kind: str


@dataclass
class InventoryReport:
    findings: list[Finding]
    factory_calls: dict[str, int]
    approved_imports: dict[str, str]
    approved_direct_calls: dict[str, str]
    non_http_infrastructure: dict[str, str]
    non_runtime_egress_scope: dict[str, str]

    def as_json(self) -> str:
        return json.dumps(
            {
                "findings": [asdict(finding) for finding in self.findings],
                "factory_calls": self.factory_calls,
                "expected_factory_calls": EXPECTED_FACTORY_CALLS,
                "approved_imports": self.approved_imports,
                "approved_direct_calls": self.approved_direct_calls,
                "non_http_infrastructure": self.non_http_infrastructure,
                "non_runtime_egress_scope": self.non_runtime_egress_scope,
            },
            indent=2,
            sort_keys=True,
        )


class _Visitor(ast.NodeVisitor):
    def __init__(self, path: str):
        self.path = path
        self.aliases: dict[str, str] = {}
        self.context: list[str] = []
        self.findings: list[Finding] = []
        self.factory_calls: Counter[str] = Counter()
        self.direct_calls: Counter[tuple[str, str, str]] = Counter()
        self.approved_imports: dict[str, str] = {}

    def _context_name(self) -> str:
        return ".".join(self.context) if self.context else "<module>"

    def _record_import(self, module: str, line: int) -> None:
        matched = next(
            (
                root
                for root in FORBIDDEN_IMPORT_ROOTS
                if module == root or module.startswith(root + ".")
            ),
            None,
        )
        if matched is None:
            return
        key = (self.path, matched)
        reason = APPROVED_IMPORTS.get(key)
        if reason is None:
            self.findings.append(
                Finding(self.path, line, self._context_name(), matched, "import")
            )
        else:
            self.approved_imports[f"{self.path}:{matched}"] = reason

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            bound = alias.asname or alias.name.split(".", 1)[0]
            self.aliases[bound] = alias.name
            self._record_import(alias.name, node.lineno)
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        self._record_import(module, node.lineno)
        for alias in node.names:
            if alias.name == "*":
                continue
            bound = alias.asname or alias.name
            self.aliases[bound] = f"{module}.{alias.name}" if module else alias.name
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.context.append(node.name)
        self.generic_visit(node)
        self.context.pop()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.context.append(node.name)
        self.generic_visit(node)
        self.context.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def _qualified(self, node: ast.expr) -> str:
        if isinstance(node, ast.Name):
            return self.aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            parent = self._qualified(node.value)
            return f"{parent}.{node.attr}" if parent else node.attr
        return ""

    def visit_Call(self, node: ast.Call) -> None:
        symbol = self._qualified(node.func)
        context = self._context_name()
        short_symbol = symbol.rsplit(".", 1)[-1]
        if short_symbol in {"create_sync_client", "create_async_client"}:
            key = f"{self.path}::{context}:{short_symbol}"
            self.factory_calls[key] += 1
        if symbol in FORBIDDEN_CALLS:
            key = (self.path, context, symbol)
            self.direct_calls[key] += 1
            if key not in APPROVED_DIRECT_CALLS:
                self.findings.append(
                    Finding(self.path, node.lineno, context, symbol, "call")
                )
        self.generic_visit(node)


def _scan_source_details(source: str, path: str) -> _Visitor:
    tree = ast.parse(source, filename=path)
    visitor = _Visitor(path)
    visitor.visit(tree)
    for key, count in visitor.direct_calls.items():
        expected = APPROVED_DIRECT_CALLS.get(key)
        if expected is not None and count != expected[0]:
            visitor.findings.append(
                Finding(
                    path,
                    0,
                    key[1],
                    key[2],
                    f"approved_call_count_expected_{expected[0]}_got_{count}",
                )
            )
    return visitor


def scan_source(source: str, path: str) -> list[Finding]:
    return sorted(_scan_source_details(source, path).findings)


def _python_files(root: Path) -> Iterable[Path]:
    for item in PRODUCTION_PATHS:
        candidate = root / item
        if candidate.is_file() and candidate.suffix == ".py":
            yield candidate
        elif candidate.is_dir():
            yield from sorted(candidate.rglob("*.py"))


def scan_production_tree(root: Path) -> InventoryReport:
    findings: list[Finding] = []
    factory_calls: Counter[str] = Counter()
    approved_imports: dict[str, str] = {}
    observed_direct_calls: Counter[tuple[str, str, str]] = Counter()
    for file_path in _python_files(root):
        relative = file_path.relative_to(root).as_posix()
        visitor = _scan_source_details(file_path.read_text(encoding="utf-8"), relative)
        findings.extend(visitor.findings)
        factory_calls.update(visitor.factory_calls)
        approved_imports.update(visitor.approved_imports)
        observed_direct_calls.update(visitor.direct_calls)

    for key, (expected_count, _reason) in APPROVED_DIRECT_CALLS.items():
        count = observed_direct_calls.get(key, 0)
        if count != expected_count:
            findings.append(
                Finding(
                    key[0],
                    0,
                    key[1],
                    key[2],
                    f"approved_call_count_expected_{expected_count}_got_{count}",
                )
            )

    approved_direct = {
        f"{path}::{context}:{symbol}": reason
        for (path, context, symbol), (_count, reason) in APPROVED_DIRECT_CALLS.items()
    }
    return InventoryReport(
        findings=sorted(set(findings)),
        factory_calls=dict(sorted(factory_calls.items())),
        approved_imports=dict(sorted(approved_imports.items())),
        approved_direct_calls=dict(sorted(approved_direct.items())),
        non_http_infrastructure=NON_HTTP_INFRASTRUCTURE,
        non_runtime_egress_scope=NON_RUNTIME_EGRESS_SCOPE,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--root", type=Path, default=Path(__file__).resolve().parents[1]
    )
    args = parser.parse_args()
    report = scan_production_tree(args.root.resolve())
    print(report.as_json())
    return int(bool(report.findings or report.factory_calls != EXPECTED_FACTORY_CALLS))


if __name__ == "__main__":
    raise SystemExit(main())

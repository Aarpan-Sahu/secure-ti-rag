"""Command-line interface: ``tirag <command>``.

    tirag db-init                       create the schema (pgvector backend)
    tirag ingest --source fixtures      ingest synthetic demo data (dev only)
    tirag ingest --source all --full    ingest MISP + OpenCTI
    tirag serve                         run the API with uvicorn
    tirag ask "question"                ask from the terminal (clearance via --tlp)
    tirag eval                          run the offline RAG evaluation harness
    tirag keygen --name alice           mint an API key and its configuration entry
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from tirag.config import Settings, get_settings
from tirag.logging_setup import configure_logging
from tirag.models import TLP


def _sources(value: str, settings: Settings) -> list[str]:
    if value == "all":
        out = []
        if settings.misp_url:
            out.append("misp")
        if settings.opencti_url:
            out.append("opencti")
        if not out:
            raise SystemExit("no sources configured: set TIRAG_MISP_URL and/or TIRAG_OPENCTI_URL")
        return out
    return [value]


def cmd_db_init(_: argparse.Namespace) -> int:
    from tirag.store import build_store

    store = build_store(get_settings())
    store.init_schema()
    store.close()
    print("schema ready")
    return 0


def cmd_ingest(args: argparse.Namespace) -> int:
    from tirag.connectors import ConnectorError, build_connectors
    from tirag.embeddings import build_embeddings
    from tirag.ingest.pipeline import ingest_connector
    from tirag.store import build_store

    settings = get_settings()
    store = build_store(settings)
    store.init_schema()
    embeddings = build_embeddings(settings)
    exit_code = 0
    try:
        connectors = build_connectors(settings, _sources(args.source, settings))
    except ConnectorError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    for connector in connectors:
        report = ingest_connector(connector, store, embeddings, settings, full=args.full)
        print(json.dumps(report.as_dict()))
        if report.errors:
            exit_code = 1
    store.close()
    return exit_code


def cmd_serve(args: argparse.Namespace) -> int:
    import uvicorn

    uvicorn.run(
        "tirag.api.app:app_factory",
        factory=True,
        host=args.host,
        port=args.port,
        log_config=None,
        proxy_headers=True,
        forwarded_allow_ips=args.forwarded_allow_ips,
        server_header=False,
    )
    return 0


def cmd_ask(args: argparse.Namespace) -> int:
    from tirag.api.app import build_service
    from tirag.rag.chain import Clearance, GuardrailViolation

    settings = get_settings()
    service = build_service(settings)
    clearance = Clearance(max_tlp=TLP.parse(args.tlp, TLP.CLEAR))
    try:
        result = service.answer(args.question, clearance)
    except GuardrailViolation as exc:
        print(f"rejected: {exc.reason}", file=sys.stderr)
        return 3
    print(result.answer)
    for c in result.citations:
        print(f"  [{c.n}] {c.doc_type} | {c.title} | {c.source} | TLP:{c.tlp} | {c.url}")
    if result.flags:
        print("flags:", ", ".join(result.flags))
    return 0


def cmd_eval(args: argparse.Namespace) -> int:
    from tirag.evalkit import run_eval

    report = run_eval(Path(args.golden), live=args.live)
    print(json.dumps(report.summary(), indent=2))
    for failure in report.failures():
        print("FAIL:", failure, file=sys.stderr)
    return 0 if report.passed(args.min_hit_rate) else 1


def cmd_keygen(args: argparse.Namespace) -> int:
    from tirag.security.auth import generate_api_key

    key, digest = generate_api_key()
    entry = {"name": args.name, "sha256": digest, "role": args.role, "max_tlp": args.max_tlp}
    if args.expires:
        entry["expires"] = args.expires
    print("API key (shown once, store it in your password manager / secret store):")
    print(f"  {key}")
    print("Add this entry to TIRAG_API_KEYS_JSON (a JSON list):")
    print(json.dumps(entry))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="tirag", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("db-init", help="create database schema").set_defaults(func=cmd_db_init)

    p = sub.add_parser("ingest", help="ingest feeds into the index")
    p.add_argument("--source", choices=["misp", "opencti", "fixtures", "all"], default="all")
    p.add_argument("--full", action="store_true", help="ignore the stored sync cursor")
    p.set_defaults(func=cmd_ingest)

    p = sub.add_parser("serve", help="run the API")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8080)
    p.add_argument("--forwarded-allow-ips", default="127.0.0.1")
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("ask", help="ask a question from the terminal")
    p.add_argument("question")
    p.add_argument("--tlp", default="GREEN", help="clearance used for retrieval (default GREEN)")
    p.set_defaults(func=cmd_ask)

    p = sub.add_parser("eval", help="run the offline RAG evaluation")
    p.add_argument("--golden", default="eval/golden_set.json")
    p.add_argument("--min-hit-rate", type=float, default=0.85)
    p.add_argument("--live", action="store_true", help="use the embedding/LLM providers from the environment")
    p.set_defaults(func=cmd_eval)

    p = sub.add_parser("keygen", help="mint an API key")
    p.add_argument("--name", required=True)
    p.add_argument("--role", choices=["analyst", "admin"], default="analyst")
    p.add_argument("--max-tlp", default="GREEN")
    p.add_argument("--expires", help="ISO date, e.g. 2027-01-31")
    p.set_defaults(func=cmd_keygen)

    args = parser.parse_args(argv)
    configure_logging(get_settings().log_level if args.command != "keygen" else "WARNING")
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())

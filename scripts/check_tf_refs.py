#!/usr/bin/env python3
"""Static consistency check for the Terraform code (no terraform binary, no cloud access needed).

This is NOT a substitute for `terraform validate` / `plan` (CI runs those). It catches the class of
mistakes that bite first when a stack has never been planned: wrong variable / output / resource /
local references, module calls with missing or unknown arguments, and unused declarations.

    python scripts/check_tf_refs.py infrastructure/terraform
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import hcl2

REF = re.compile(r"\b(var|local|module)\.([A-Za-z_][A-Za-z0-9_-]*)(?:\.([A-Za-z_][A-Za-z0-9_-]*))?")
RES = re.compile(r"(?<![\w.\"])((?:data\.)?aws_[a-z0-9_]+)\.([A-Za-z_][A-Za-z0-9_-]*)")


def _scalar(value: object) -> str:
    """python-hcl2 wraps attribute values in a one-element list in some files; unwrap."""
    while isinstance(value, list) and len(value) == 1:
        value = value[0]
    return str(value)


def unq(key: str) -> str:
    return key.strip('"')


def load(path: Path) -> dict:
    with path.open() as fh:
        return hcl2.load(fh)


def strings(node: object):
    """Yield every expression string (python-hcl2 renders expressions as '${...}')."""
    if isinstance(node, str):
        if "${" in node:
            yield node
    elif isinstance(node, dict):
        for v in node.values():
            yield from strings(v)
    elif isinstance(node, list):
        for v in node:
            yield from strings(v)


def merge(dirpath: Path) -> dict:
    out: dict = {
        "variable": {},
        "output": {},
        "locals": {},
        "resource": set(),
        "data": set(),
        "module": {},
        "exprs": [],
    }
    for tf in sorted(dirpath.glob("*.tf")):
        doc = load(tf)
        out["exprs"].extend(strings({k: v for k, v in doc.items() if k != "variable"}))
        # variable defaults/validation may reference other vars (TF >= 1.9) - scan them too
        out["exprs"].extend(strings(doc.get("variable", [])))
        for v in doc.get("variable", []):
            for name, body in v.items():
                out["variable"][unq(name)] = body
        for o in doc.get("output", []):
            for name, body in o.items():
                out["output"][unq(name)] = body
        for lc in doc.get("locals", []):
            out["locals"].update({unq(k): v for k, v in lc.items() if k != "__is_block__"})
        for r in doc.get("resource", []):
            for rtype, items in r.items():
                for rname in items:
                    out["resource"].add(f"{unq(rtype)}.{unq(rname)}")
        for d in doc.get("data", []):
            for rtype, items in d.items():
                for rname in items:
                    out["data"].add(f"data.{unq(rtype)}.{unq(rname)}")
        for m in doc.get("module", []):
            for name, body in m.items():
                out["module"][unq(name)] = {
                    k: (unq(_scalar(v)) if k == "source" else v) for k, v in body.items()
                }
    return out


def check_dir(dirpath: Path, errors: list[str], warnings: list[str]) -> None:
    info = merge(dirpath)
    rel = dirpath.as_posix()
    scan = "\n".join(info["exprs"])

    used_vars: set[str] = set()
    for kind, name, attr in REF.findall(scan):
        if kind == "var":
            used_vars.add(name)
            if name not in info["variable"]:
                errors.append(f"{rel}: var.{name} is not declared")
        elif kind == "local":
            if name not in info["locals"]:
                errors.append(f"{rel}: local.{name} is not defined")
        elif kind == "module":
            if name not in info["module"]:
                errors.append(f"{rel}: module.{name} is not declared")
            elif attr:
                src = (dirpath / info["module"][name]["source"]).resolve()
                if attr not in merge(src)["output"]:
                    errors.append(f"{rel}: module.{name}.{attr} - module has no such output")
    for name in info["variable"]:
        if name not in used_vars:
            warnings.append(f"{rel}: variable {name} is never used")
    for rtype, rname in RES.findall(scan):
        full = f"{rtype}.{rname}"
        pool = info["data"] if full.startswith("data.") else info["resource"]
        if full not in pool:
            errors.append(f"{rel}: reference to undeclared {full}")

    for mname, body in info["module"].items():
        src = (dirpath / body["source"]).resolve()
        if not src.is_dir():
            errors.append(f"{rel}: module.{mname} source {body['source']} not found")
            continue
        callee = merge(src)
        meta = {"source", "for_each", "count", "depends_on", "providers", "version"}
        passed = {k for k in body if k not in meta and not k.startswith("__")}
        for var, vbody in callee["variable"].items():
            if "default" not in vbody and var not in passed:
                errors.append(f"{rel}: module.{mname} is missing required argument '{var}'")
        for arg in passed:
            if arg not in callee["variable"]:
                errors.append(f"{rel}: module.{mname} passes unknown argument '{arg}'")


def main(argv: list[str]) -> int:
    root = Path(argv[1] if len(argv) > 1 else "infrastructure/terraform")
    dirs = sorted({p.parent for p in root.rglob("*.tf")})
    errors: list[str] = []
    warnings: list[str] = []
    for d in dirs:
        check_dir(d, errors, warnings)
    for w in warnings:
        print(f"warning: {w}")
    for e in errors:
        print(f"ERROR: {e}")
    print(f"checked {len(dirs)} module directories: {len(errors)} errors, {len(warnings)} warnings")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))

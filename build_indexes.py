#!/usr/bin/env python3

import json
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path("/root/agent-stack")
SOURCES = ROOT / "sources"
DATA = ROOT / "data"

PUBLIC_README = SOURCES / "public-apis" / "README.md"
BUILDX_README = SOURCES / "build-your-own-x" / "README.md"

DATA.mkdir(parents=True, exist_ok=True)


def clean(text):
    text = text or ""
    text = re.sub(r"<[^>]+>", "", text)
    text = re.sub(r"`([^`]*)`", r"\1", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def git_commit(repo):
    try:
        return subprocess.check_output(
            ["git", "-C", str(repo), "rev-parse", "HEAD"],
            text=True
        ).strip()
    except Exception:
        return None


# ============================================================
# PUBLIC APIS
# ============================================================

def parse_public_apis():
    lines = PUBLIC_README.read_text(
        encoding="utf-8",
        errors="replace"
    ).splitlines()

    category = None
    in_table = False
    records = []

    for line in lines:
        heading = re.match(r"^###\s+(.+?)\s*$", line)

        if heading:
            category = clean(heading.group(1))
            in_table = False
            continue

        compact = line.lower().replace(" ", "")

        if (
            category
            and "api|description|auth|https|cors" in compact
        ):
            in_table = True
            continue

        if not in_table:
            continue

        if not line.strip():
            in_table = False
            continue

        if not line.lstrip().startswith("|"):
            continue

        cells = [
            c.strip()
            for c in line.strip().strip("|").split("|")
        ]

        if len(cells) < 5:
            continue

        if all(
            re.fullmatch(
                r":?-{3,}:?",
                c.replace(" ", "")
            )
            for c in cells[:5]
        ):
            continue

        match = re.search(
            r"\[([^\]]+)\]\((https?://[^)]+)\)",
            cells[0]
        )

        if not match:
            continue

        name = clean(match.group(1))
        url = match.group(2).strip()

        https_raw = clean(cells[3]).lower()

        if https_raw == "yes":
            https = True
        elif https_raw == "no":
            https = False
        else:
            https = None

        records.append({
            "category": category,
            "name": name,
            "description": clean(cells[1]),
            "auth": clean(cells[2]),
            "https": https,
            "cors": clean(cells[4]),
            "url": url
        })

    seen = set()
    unique = []

    for item in records:
        key = (
            item["category"].lower(),
            item["name"].lower(),
            item["url"].lower()
        )

        if key in seen:
            continue

        seen.add(key)
        unique.append(item)

    return unique


# ============================================================
# BUILD YOUR OWN X
# ============================================================

def parse_buildx():
    lines = BUILDX_README.read_text(
        encoding="utf-8",
        errors="replace"
    ).splitlines()

    category = None
    records = []

    primary_pattern = re.compile(
        r'^\s*[*-]\s+'
        r'\[\*\*(.+?)\*\*:\s*'
        r'_?(.*?)_?'
        r'\]\((https?://[^)]+)\)'
        r'(?:\s+\[([^\]]+)\])?'
        r'\s*$'
    )

    generic_pattern = re.compile(
        r'^\s*[*-]\s+'
        r'\[([^\]]+)\]\((https?://[^)]+)\)'
    )

    for line in lines:
        heading = re.match(
            r'^#### Build your own\s+`(.+?)`\s*$',
            line
        )

        if heading:
            category = clean(heading.group(1))
            continue

        if not category:
            continue

        match = primary_pattern.match(line)

        if match:
            language = clean(match.group(1))
            title = clean(match.group(2))
            url = match.group(3).strip()
            media = clean(match.group(4) or "")

            records.append({
                "category": category,
                "language": language,
                "title": title,
                "url": url,
                "media": media
            })

            continue

        # Fallback for any useful tutorial links that do not
        # follow the standard language/title format.
        match = generic_pattern.match(line)

        if match:
            title = clean(match.group(1))
            url = match.group(2).strip()

            if "Back to" in title:
                continue

            records.append({
                "category": category,
                "language": "Unknown",
                "title": title,
                "url": url,
                "media": ""
            })

    seen = set()
    unique = []

    for item in records:
        key = (
            item["category"].lower(),
            item["title"].lower(),
            item["url"].lower()
        )

        if key in seen:
            continue

        seen.add(key)
        unique.append(item)

    return unique


public_apis = parse_public_apis()
buildx = parse_buildx()

timestamp = datetime.now(timezone.utc).isoformat()

public_payload = {
    "source": "public-apis/public-apis",
    "source_commit": git_commit(
        SOURCES / "public-apis"
    ),
    "generated_at": timestamp,
    "count": len(public_apis),
    "items": public_apis
}

buildx_payload = {
    "source": "codecrafters-io/build-your-own-x",
    "source_commit": git_commit(
        SOURCES / "build-your-own-x"
    ),
    "generated_at": timestamp,
    "count": len(buildx),
    "items": buildx
}

(DATA / "public_apis.json").write_text(
    json.dumps(
        public_payload,
        indent=2,
        ensure_ascii=False
    ),
    encoding="utf-8"
)

(DATA / "buildx.json").write_text(
    json.dumps(
        buildx_payload,
        indent=2,
        ensure_ascii=False
    ),
    encoding="utf-8"
)

print("Indexes created successfully.")
print(f"Public APIs:       {len(public_apis)}")
print(f"Build-X tutorials: {len(buildx)}")
print()
print(DATA / "public_apis.json")
print(DATA / "buildx.json")

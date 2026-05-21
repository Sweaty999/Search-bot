from __future__ import annotations

import csv
import dataclasses
import json
import os
import shlex
import shutil
import subprocess
import threading
from pathlib import Path
from string import Template
from typing import Any, Dict, Iterable, List, Sequence
from urllib.parse import urlparse
from urllib.parse import quote
from urllib.request import Request, urlopen

from tools.analyzer import AnalysisReport, Finding


@dataclasses.dataclass(frozen=True)
class ToolSpec:
    key: str
    name: str
    category: str
    kinds: tuple[str, ...]
    command: tuple[str, ...]
    timeout: int = 120
    personal: bool = False
    output_parser: str = "auto"
    note: str = ""
    repository: str = ""
    install: str = ""
    stdin_template: str = ""
    max_stdout_lines: int = 0


TOOL_SPECS = [
    ToolSpec(
        "spiderfoot",
        "SpiderFoot",
        "infrastructure",
        ("domain", "email", "ip", "url"),
        ("python", "{path}", "-s", "{target}", "-o", "json", "-u", "passive", "-x"),
        timeout=30,
        note="Пассивная инфраструктурная разведка.",
    ),
    ToolSpec(
        "theharvester",
        "theHarvester",
        "infrastructure",
        ("domain",),
        ("theHarvester", "-d", "{target}", "-b", "crtsh,rapiddns,urlscan", "-q", "-f", "{output_stem_name}"),
        timeout=240,
        output_parser="json_file",
        note="GitHub OSINT tool for emails, subdomains, IPs and URLs from public sources.",
        repository="https://github.com/laramies/theHarvester",
        install="git clone https://github.com/laramies/theHarvester && cd theHarvester && uv sync",
    ),
    ToolSpec(
        "subfinder",
        "Subfinder",
        "infrastructure",
        ("domain",),
        ("subfinder", "-d", "{target}", "-silent", "-oJ", "-o", "{output_file}"),
        timeout=180,
        output_parser="json_lines_file",
        note="GitHub passive subdomain discovery from ProjectDiscovery.",
        repository="https://github.com/projectdiscovery/subfinder",
        install="go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
    ),
    ToolSpec(
        "amass_passive",
        "OWASP Amass passive",
        "infrastructure",
        ("domain",),
        ("amass", "enum", "-passive", "-d", "{target}", "-include", "crtsh,hackertarget", "-o", "{output_file}", "-timeout", "1", "-silent"),
        timeout=180,
        output_parser="text_file",
        note="OWASP Amass in passive mode for attack-surface mapping from OSINT sources.",
        repository="https://github.com/owasp-amass/amass",
        install="go install -v github.com/owasp-amass/amass/v4/...@latest",
    ),
    ToolSpec(
        "assetfinder",
        "Assetfinder",
        "infrastructure",
        ("domain",),
        ("assetfinder", "--subs-only", "{target}"),
        timeout=120,
        note="GitHub tool for related domains and subdomains.",
        repository="https://github.com/tomnomnom/assetfinder",
        install="go install github.com/tomnomnom/assetfinder@latest",
    ),
    ToolSpec(
        "waybackurls",
        "Waybackurls",
        "url",
        ("domain", "url"),
        ("waybackurls",),
        timeout=180,
        note="GitHub tool that asks the Wayback Machine for known URLs of a domain.",
        repository="https://github.com/tomnomnom/waybackurls",
        install="go install github.com/tomnomnom/waybackurls@latest",
        stdin_template="{target}\n",
    ),
    ToolSpec(
        "urlfinder",
        "URLFinder",
        "url",
        ("domain", "url"),
        ("urlfinder", "-d", "{target}", "-j", "-o", "{output_file}", "-silent", "-max-time", "1"),
        timeout=180,
        output_parser="json_lines_file",
        note="GitHub passive URL discovery from public URL archives.",
        repository="https://github.com/projectdiscovery/urlfinder",
        install="go install -v github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest",
    ),
    ToolSpec(
        "socialscan",
        "socialscan",
        "username",
        ("username", "email"),
        ("socialscan", "{target}", "--show-urls", "--json", "{output_file}"),
        timeout=120,
        personal=True,
        output_parser="json_file",
        note="GitHub CLI for checking public username/email usage signals on supported platforms.",
        repository="https://github.com/iojw/socialscan",
        install="pip install socialscan",
    ),
    ToolSpec(
        "maigret",
        "Maigret",
        "username",
        ("username", "telegram"),
        ("maigret", "{target}", "--json", "simple"),
        timeout=180,
        personal=True,
        note="Поиск username по публичным сайтам.",
    ),
    ToolSpec(
        "sherlock",
        "Sherlock",
        "username",
        ("username", "telegram"),
        ("sherlock", "{target}", "--print-found", "--no-color", "--csv", "--folderoutput", "{output_dir}"),
        timeout=180,
        personal=True,
        output_parser="sherlock_csv",
        note="Поиск username по соцсетям и сайтам.",
    ),
    ToolSpec(
        "blackbird",
        "Blackbird",
        "username",
        ("username", "telegram", "email"),
        ("blackbird", "--username", "{target}", "--json"),
        timeout=180,
        personal=True,
        note="Поиск username/email по публичным платформам.",
    ),
    ToolSpec(
        "social_analyzer",
        "Social Analyzer",
        "username",
        ("username", "telegram"),
        ("social-analyzer", "--username", "{target}", "--metadata", "--top", "100", "--output", "json"),
        timeout=180,
        personal=True,
        note="Агрегатор публичных социальных профилей.",
    ),
    ToolSpec(
        "holehe",
        "Holehe",
        "email",
        ("email",),
        ("holehe", "{target}", "--no-color"),
        timeout=120,
        personal=True,
        note="Проверка публичных признаков регистрации email на сервисах.",
    ),
    ToolSpec(
        "ghunt",
        "GHunt",
        "email",
        ("email",),
        ("ghunt", "email", "{target}", "--json", "{output_file}"),
        timeout=180,
        personal=True,
        output_parser="json_file",
        note="Google-account OSINT для разрешённых проверок.",
    ),
    ToolSpec(
        "h8mail",
        "h8mail",
        "breach",
        ("email",),
        ("h8mail", "-t", "{target}", "-j", "{output_file}"),
        timeout=180,
        personal=True,
        output_parser="json_file",
        note="Поиск публичных утечек/компрометаций email.",
    ),
    ToolSpec(
        "phoneinfoga",
        "PhoneInfoga",
        "phone",
        ("phone",),
        ("phoneinfoga", "scan", "-n", "{target}", "--output", "json"),
        timeout=180,
        personal=True,
        note="Технический OSINT по номеру телефона.",
    ),
    ToolSpec(
        "ignorant",
        "ignorant",
        "phone",
        ("phone",),
        ("ignorant", "{target}", "--no-color"),
        timeout=120,
        personal=True,
        note="Проверка публичных признаков регистрации номера на сервисах.",
    ),
    ToolSpec(
        "detectdee",
        "detectDee",
        "email",
        ("email", "username"),
        ("detectdee", "{target}"),
        timeout=120,
        personal=True,
        note="Дополнительная проверка email/username, если CLI установлен.",
    ),
    ToolSpec(
        "telepathy",
        "Telepathy",
        "telegram",
        ("telegram",),
        ("telepathy", "{target}"),
        timeout=120,
        personal=True,
        note="Telegram OSINT runner, если установлен локально.",
    ),
    ToolSpec(
        "telerecon",
        "Telerecon",
        "telegram",
        ("telegram",),
        ("telerecon", "{target}"),
        timeout=120,
        personal=True,
        note="Telegram reconnaissance runner, если установлен локально.",
    ),
]


def _enabled(name: str, default: bool = False) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on", "y"}


def _timeout(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)))
    except ValueError:
        return default


def _max_stdout_lines(spec: ToolSpec) -> int:
    try:
        value = int(os.getenv(f"{spec.key.upper()}_MAX_STDOUT_LINES", str(spec.max_stdout_lines)))
    except ValueError:
        value = spec.max_stdout_lines
    return max(0, value)


def _limit_text(value: str, limit: int = 24_000) -> str:
    value = value.strip()
    if len(value) <= limit:
        return value
    return value[:limit] + "\n...[truncated]"


def _limit_json(value: Any, depth: int = 0) -> Any:
    if depth > 5:
        return "..."
    if isinstance(value, dict):
        return {str(key): _limit_json(item, depth + 1) for key, item in list(value.items())[:80]}
    if isinstance(value, list):
        return [_limit_json(item, depth + 1) for item in value[:120]]
    if isinstance(value, str) and len(value) > 1400:
        return value[:1400] + "...[truncated]"
    return value


def _clean_target(kind: str, value: str) -> str:
    if kind == "telegram":
        return value.lstrip("@")
    if kind == "url":
        parsed = urlparse(value if "://" in value else f"https://{value}")
        return (parsed.hostname or value).strip("[]")
    return value


def _targets_for_tool(report: AnalysisReport, spec: ToolSpec) -> List[tuple[str, str]]:
    seen = set()
    result: List[tuple[str, str]] = []
    for indicator in report.indicators:
        if not indicator.valid or indicator.kind not in spec.kinds:
            continue
        target = _clean_target(indicator.kind, indicator.normalized)
        key = (indicator.kind, target.lower())
        if key in seen:
            continue
        result.append((indicator.kind, target))
        seen.add(key)

    limit = _timeout(f"{spec.key.upper()}_MAX_TARGETS", _timeout("TOOL_RUNNER_MAX_TARGETS", 2))
    return result[: max(1, limit)]


def _tool_output_dir(report: AnalysisReport, spec: ToolSpec) -> Path:
    base = Path(os.getenv("TOOL_OUTPUT_DIR", "reports/tool-runs")).resolve()
    slug = "".join(char if char.isalnum() else "_" for char in report.generated_at[:19])
    path = base / slug / spec.key
    path.mkdir(parents=True, exist_ok=True)
    return path


def _tool_path(spec: ToolSpec) -> str:
    raw = os.getenv(f"{spec.key.upper()}_PATH", "").strip()
    if raw:
        path = Path(raw)
        if path.is_dir() and spec.key == "spiderfoot":
            path = path / "sf.py"
        return str(path)
    if spec.key == "spiderfoot":
        return "sf.py"
    return spec.command[0]


def _token_values(spec: ToolSpec, target: str, output_dir: Path) -> Dict[str, str]:
    output_file = output_dir / f"{spec.key}_{''.join(ch if ch.isalnum() else '_' for ch in target)[:48]}.json"
    return {
        "target": target,
        "quoted_target": shlex.quote(target),
        "output_dir": str(output_dir),
        "output_file": str(output_file),
        "output_stem": str(output_file.with_suffix("")),
        "output_stem_name": output_file.with_suffix("").name,
        "path": _tool_path(spec),
    }


def _custom_command(spec: ToolSpec) -> str:
    return os.getenv(f"{spec.key.upper()}_COMMAND", "").strip()


def _stdin_for_tool(spec: ToolSpec, target: str, output_dir: Path) -> str | None:
    template = os.getenv(f"{spec.key.upper()}_STDIN", spec.stdin_template).strip("\r")
    if not template:
        return None
    values = _token_values(spec, target, output_dir)
    return Template(template).safe_substitute(values)


def _build_command(spec: ToolSpec, target: str, output_dir: Path) -> List[str]:
    values = _token_values(spec, target, output_dir)
    custom = _custom_command(spec)
    if custom:
        command = Template(custom).safe_substitute(values)
        return shlex.split(command, posix=os.name != "nt")

    rendered = []
    for part in spec.command:
        rendered.append(Template(part).safe_substitute(values))

    if spec.key == "spiderfoot":
        python_bin = os.getenv("SPIDERFOOT_PYTHON", rendered[0])
        rendered[0] = python_bin
        modules = os.getenv("SPIDERFOOT_MODULES", "").strip()
        if modules:
            rendered = [rendered[0], rendered[1], "-s", target, "-o", "json", "-m", modules]
        else:
            rendered = [
                rendered[0],
                rendered[1],
                "-s",
                target,
                "-o",
                "json",
                "-u",
                os.getenv("SPIDERFOOT_USECASE", "passive"),
                "-x",
            ]
    return rendered


def _command_available(command: Sequence[str], spec: ToolSpec) -> tuple[bool, str | None]:
    if not command:
        return False, "Команда не сформирована."
    executable = command[0]
    if spec.key == "spiderfoot" and len(command) > 1:
        sf_path = Path(command[1])
        if not sf_path.exists():
            return False, "SPIDERFOOT_PATH не задан или sf.py не найден."
        return True, None
    if Path(executable).exists() or shutil.which(executable):
        return True, None
    return False, f"Не найден исполняемый файл: {executable}. Укажи {spec.key.upper()}_COMMAND или установи CLI."


def _tool_availability(spec: ToolSpec) -> Dict[str, Any]:
    executable = _tool_path(spec)
    custom = _custom_command(spec)

    if custom:
        values = {
            "target": "example",
            "quoted_target": "example",
            "output_dir": "reports/tool-runs",
            "output_file": "reports/tool-runs/output.json",
            "output_stem": "reports/tool-runs/output",
            "output_stem_name": "output",
            "path": executable,
        }
        try:
            parts = shlex.split(Template(custom).safe_substitute(values), posix=os.name != "nt")
            if parts:
                executable = parts[0]
        except ValueError:
            pass

    if spec.key == "spiderfoot":
        candidate = Path(executable)
        if candidate.is_dir():
            candidate = candidate / "sf.py"
        available = candidate.exists()
        return {
            "enabled": _enabled(f"ENABLE_{spec.key.upper()}", False),
            "available": available,
            "executable": str(candidate),
            "hint": "" if available else "Set SPIDERFOOT_PATH to sf.py or install SpiderFoot.",
            "repository": spec.repository,
            "install": spec.install,
        }

    local_path = Path(executable)
    resolved = str(local_path) if local_path.exists() else shutil.which(executable)
    return {
        "enabled": _enabled(f"ENABLE_{spec.key.upper()}", False),
        "available": bool(resolved),
        "executable": resolved or executable,
        "hint": "" if resolved else f"Install {spec.name} CLI or set {spec.key.upper()}_COMMAND.",
        "repository": spec.repository,
        "install": spec.install,
    }


def _parse_jsonish(text: str) -> Any | None:
    text = text.strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    rows = []
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{") and not line.startswith("["):
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows or None


def _read_json_file(path: Path) -> Any | None:
    if not path.exists() or path.stat().st_size > 15_000_000:
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return None


def _read_json_lines_file(path: Path) -> List[Any]:
    if not path.exists() or path.stat().st_size > 15_000_000:
        return []
    rows = []
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
            if len(rows) >= 250:
                break
    except OSError:
        return []
    return rows


def _read_text_file(path: Path) -> str | None:
    if not path.exists() or path.stat().st_size > 15_000_000:
        return None
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _read_csv_files(output_dir: Path) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    for path in output_dir.glob("*.csv"):
        try:
            with path.open("r", encoding="utf-8", errors="replace", newline="") as handle:
                reader = csv.DictReader(handle)
                for row in reader:
                    rows.append(dict(row))
                    if len(rows) >= 250:
                        return rows
        except OSError:
            continue
    return rows


def _summarize_text(text: str) -> Dict[str, Any]:
    useful_lines = []
    for line in text.splitlines():
        clean = line.strip()
        if not clean:
            continue
        if clean.lower().startswith(("usage:", "warning:", "debug:")):
            continue
        useful_lines.append(clean)
        if len(useful_lines) >= 160:
            break
    return {"raw": _limit_text("\n".join(useful_lines) or text)}


def _parse_output(spec: ToolSpec, stdout: str, output_file: Path, output_dir: Path) -> Dict[str, Any]:
    if spec.output_parser == "json_file":
        parsed = _read_json_file(output_file)
        if parsed is not None:
            return {"json": _limit_json(parsed), "output_file": str(output_file)}

    if spec.output_parser == "json_lines_file":
        rows = _read_json_lines_file(output_file)
        if rows:
            return {"json_lines": _limit_json(rows), "output_file": str(output_file)}

    if spec.output_parser == "text_file":
        text = _read_text_file(output_file)
        if text:
            return {"text_file": _summarize_text(text), "output_file": str(output_file)}

    if spec.output_parser == "sherlock_csv":
        rows = _read_csv_files(output_dir)
        if rows:
            return {"csv_rows": _limit_json(rows), "output_dir": str(output_dir)}

    parsed_stdout = _parse_jsonish(stdout)
    if parsed_stdout is not None:
        return {"json": _limit_json(parsed_stdout)}

    rows = _read_csv_files(output_dir)
    if rows:
        return {"csv_rows": _limit_json(rows), "output_dir": str(output_dir)}

    return _summarize_text(stdout)


def _parsed_has_data(parsed: Dict[str, Any]) -> bool:
    for key in ("json", "json_lines", "csv_rows"):
        value = parsed.get(key)
        if value not in (None, "", [], {}):
            return True
    text_file = parsed.get("text_file")
    if isinstance(text_file, dict) and text_file.get("raw"):
        return True
    if parsed.get("raw"):
        return True
    return False


def _wayback_cdx_fallback(target: str, limit: int = 500) -> str:
    host = _clean_target("url", target).strip(".")
    if not host:
        return ""
    url = (
        "https://web.archive.org/cdx"
        f"?url=*.{quote(host)}/*&output=json&fl=original&collapse=urlkey&limit={max(1, limit)}"
    )
    request = Request(url, headers={"User-Agent": "osint-bot/2.0 waybackurls-fallback"})
    try:
        with urlopen(request, timeout=20) as response:
            rows = json.loads(response.read(2_000_000).decode("utf-8", errors="replace"))
    except Exception:
        return ""
    urls = []
    for row in rows:
        if isinstance(row, list) and row and str(row[0]).lower() != "original":
            urls.append(str(row[0]))
        elif isinstance(row, str):
            urls.append(row)
        if len(urls) >= limit:
            break
    return "\n".join(urls)


def _tool_enabled(spec: ToolSpec) -> bool:
    if not _enabled("ENABLE_TOOL_RUNNERS", False):
        return False
    if spec.personal and not _enabled("ENABLE_PERSONAL_OSINT_TOOLS", False):
        return False
    return _enabled(f"ENABLE_{spec.key.upper()}", False)


def _run_stream_limited(
    command: Sequence[str],
    cwd: Path,
    stdin_value: str | None,
    timeout: int,
    max_lines: int,
) -> Dict[str, Any]:
    process = subprocess.Popen(
        command,
        cwd=str(cwd),
        stdin=subprocess.PIPE if stdin_value is not None else None,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
    )

    stdout_lines: List[str] = []
    stderr_parts: List[str] = []
    truncated = False

    def read_stdout() -> None:
        nonlocal truncated
        if process.stdout is None:
            return
        for line in process.stdout:
            stdout_lines.append(line)
            if max_lines and len(stdout_lines) >= max_lines:
                truncated = True
                if process.poll() is None:
                    process.kill()
                break

    def read_stderr() -> None:
        if process.stderr is None:
            return
        try:
            stderr_parts.append(process.stderr.read())
        except OSError:
            pass

    stdout_thread = threading.Thread(target=read_stdout, daemon=True)
    stderr_thread = threading.Thread(target=read_stderr, daemon=True)
    stdout_thread.start()
    stderr_thread.start()

    if process.stdin is not None:
        try:
            process.stdin.write(stdin_value or "")
            process.stdin.close()
        except OSError:
            pass

    timed_out = False
    try:
        returncode = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        if process.poll() is None:
            process.kill()
        returncode = process.wait(timeout=5)

    stdout_thread.join(timeout=3)
    stderr_thread.join(timeout=3)
    return {
        "returncode": returncode,
        "stdout": "".join(stdout_lines),
        "stderr": "".join(stderr_parts),
        "timeout": timed_out,
        "truncated": truncated,
    }


def run_tool(spec: ToolSpec, report: AnalysisReport, kind: str, target: str) -> Dict[str, Any]:
    output_dir = _tool_output_dir(report, spec)
    command = _build_command(spec, target, output_dir)
    stdin_value = _stdin_for_tool(spec, target, output_dir)
    ok, reason = _command_available(command, spec)
    if not ok:
        return {
            "ok": False,
            "configured": False,
            "error": reason,
            "command_preview": " ".join(command),
            "repository": spec.repository,
            "install": spec.install,
        }

    output_file = Path(_token_values(spec, target, output_dir)["output_file"])
    max_lines = _max_stdout_lines(spec)
    if max_lines:
        timeout_value = _timeout(f"{spec.key.upper()}_TIMEOUT", spec.timeout)
        try:
            stream_result = _run_stream_limited(command, output_dir, stdin_value, timeout_value, max_lines)
        except OSError as exc:
            return {
                "ok": False,
                "configured": True,
                "error": str(exc),
                "command": " ".join(command),
                "repository": spec.repository,
                "install": spec.install,
            }
        parsed = _parse_output(spec, stream_result["stdout"], output_file, output_dir)
        has_data = _parsed_has_data(parsed)
        fallback_used = False
        soft_success_message = ""
        if not has_data and spec.key == "waybackurls":
            fallback_stdout = _wayback_cdx_fallback(target, max_lines)
            if fallback_stdout:
                parsed = _parse_output(spec, fallback_stdout, output_file, output_dir)
                has_data = _parsed_has_data(parsed)
                fallback_used = has_data
            else:
                soft_success_message = "Waybackurls CLI ran, but the Wayback/CDX source did not return URL data before the timeout."
                parsed = {"raw": soft_success_message}
                has_data = True
        return {
            "ok": has_data or stream_result["returncode"] == 0,
            "configured": True,
            "returncode": stream_result["returncode"],
            "timeout": stream_result["timeout"],
            "truncated": stream_result["truncated"],
            "fallback_used": fallback_used,
            "soft_success": bool(soft_success_message),
            "command": " ".join(command),
            "stdin": bool(stdin_value),
            "output_dir": str(output_dir),
            "stdout": parsed,
            "stderr": _limit_text(stream_result["stderr"], 8000),
            "repository": spec.repository,
            "install": spec.install,
        }

    try:
        process = subprocess.run(
            command,
            cwd=str(output_dir),
            capture_output=True,
            input=stdin_value,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=_timeout(f"{spec.key.upper()}_TIMEOUT", spec.timeout),
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        if isinstance(stdout, bytes):
            stdout = stdout.decode("utf-8", errors="replace")
        if isinstance(stderr, bytes):
            stderr = stderr.decode("utf-8", errors="replace")
        parsed = _parse_output(spec, stdout, output_file, output_dir)
        has_data = _parsed_has_data(parsed)
        fallback_used = False
        soft_success_message = ""
        if not has_data and spec.key == "waybackurls":
            fallback_stdout = _wayback_cdx_fallback(target, _max_stdout_lines(spec) or 500)
            if fallback_stdout:
                parsed = _parse_output(spec, fallback_stdout, output_file, output_dir)
                has_data = _parsed_has_data(parsed)
                fallback_used = has_data
            else:
                soft_success_message = "Waybackurls CLI ran, but the Wayback/CDX source did not return URL data before the timeout."
                parsed = {"raw": soft_success_message}
                has_data = True
        return {
            "ok": has_data,
            "configured": True,
            "timeout": True,
            "error": (
                soft_success_message
                or f"{spec.name} timeout after {exc.timeout} seconds; partial output captured"
                if has_data
                else f"{spec.name} timeout after {exc.timeout} seconds"
            ),
            "command": " ".join(command),
            "stdin": bool(stdin_value),
            "fallback_used": fallback_used,
            "soft_success": bool(soft_success_message),
            "output_dir": str(output_dir),
            "stdout": parsed,
            "stderr": _limit_text(str(stderr), 8000),
            "repository": spec.repository,
            "install": spec.install,
        }
    except OSError as exc:
        return {
            "ok": False,
            "configured": True,
            "error": str(exc),
            "command": " ".join(command),
            "repository": spec.repository,
            "install": spec.install,
        }

    parsed = _parse_output(spec, process.stdout, output_file, output_dir)
    if spec.key == "waybackurls" and not _parsed_has_data(parsed):
        parsed = {
            "raw": "Waybackurls CLI ran, but the Wayback/CDX source returned no URL data for this target."
        }
    return {
        "ok": process.returncode == 0,
        "configured": True,
        "returncode": process.returncode,
        "command": " ".join(command),
        "stdin": bool(stdin_value),
        "output_dir": str(output_dir),
        "stdout": parsed,
        "stderr": _limit_text(process.stderr, 8000),
        "repository": spec.repository,
        "install": spec.install,
    }


def _disabled_tool_summary() -> Dict[str, Any]:
    configured_tools = {}
    for spec in TOOL_SPECS:
        availability = _tool_availability(spec)
        configured_tools[spec.key] = {
            "enabled": availability["enabled"],
            "available": availability["available"],
            "executable": availability["executable"],
            "hint": availability["hint"],
            "repository": availability["repository"],
            "install": availability["install"],
            "category": spec.category,
            "kinds": spec.kinds,
            "personal": spec.personal,
        }

    return {
        "ENABLE_TOOL_RUNNERS": _enabled("ENABLE_TOOL_RUNNERS", False),
        "ENABLE_PERSONAL_OSINT_TOOLS": _enabled("ENABLE_PERSONAL_OSINT_TOOLS", False),
        "available_tools": [key for key, value in configured_tools.items() if value["available"]],
        "enabled_tools": [key for key, value in configured_tools.items() if value["enabled"]],
        "configured_tools": configured_tools,
    }


def enrich_with_tool_runners(report: AnalysisReport) -> None:
    if not _enabled("ENABLE_TOOL_RUNNERS", False):
        report.findings.append(
            Finding(
                source="tool_orchestrator",
                title="External OSINT tools are disabled",
                level="warning",
                details=_disabled_tool_summary(),
            )
        )
        return

    report.findings.append(
        Finding(
            source="tool_inventory",
            title="External OSINT tool inventory",
            level="info",
            details=_disabled_tool_summary(),
        )
    )

    any_ran = False
    for spec in TOOL_SPECS:
        if not _tool_enabled(spec):
            continue
        for kind, target in _targets_for_tool(report, spec):
            any_ran = True
            result = run_tool(spec, report, kind, target)
            report.findings.append(
                Finding(
                    source=f"tool_{spec.key}",
                    title=f"{spec.name} OSINT runner",
                    level="info" if result.get("ok") else "warning",
                    details={
                        "tool": spec.name,
                        "tool_key": spec.key,
                        "tool_category": spec.category,
                        "target_kind": kind,
                        "target": target,
                        "personal_data_risk": spec.personal,
                        "note": spec.note,
                        **result,
                    },
                )
            )

    if not any_ran:
        report.findings.append(
            Finding(
                source="tool_orchestrator",
                title="No external OSINT tools matched this target",
                level="warning",
                details=_disabled_tool_summary(),
            )
        )

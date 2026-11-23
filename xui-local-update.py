#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""3x-ui v3.11.0: safely update LOCAL inbound flags and link IPv4 via API.

Version 3: fixes v3.11.0 local/remote filtering, adds risky inbound guard.


No inbound is modified through SQLite. For SQLite installations, the only
read-only DB query gets the optional webDomain to satisfy the HTTP Host filter.
The script never prints or writes API tokens, client UUIDs, or JSON payloads
in debug output. Backups do contain secrets and are permission-restricted.
"""

import argparse
import copy
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import sqlite3
import ssl
import subprocess
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, build_opener, HTTPSHandler, ProxyHandler

BINARY = "/usr/local/x-ui/x-ui"
TOKEN_NAME = "local-flag-rename"
BACKUP_DIR = Path("/root/xui-local-backups")

COUNTRIES = [
    ("FR", "Франция"), ("NL", "Нидерланды"), ("FI", "Финляндия"),
    ("DE", "Германия"), ("EE", "Эстония"), ("SE", "Швеция"),
    ("LV", "Латвия"), ("LT", "Литва"), ("PL", "Польша"),
    ("GB", "Великобритания"), ("US", "США"), ("CH", "Швейцария"),
    ("NO", "Норвегия"), ("AT", "Австрия"), ("BE", "Бельгия"),
    ("CZ", "Чехия"), ("IT", "Италия"), ("ES", "Испания"),
    ("TR", "Турция"), ("JP", "Япония"), ("SG", "Сингапур"),
    ("KZ", "Казахстан"), ("RU", "Россия"), ("CA", "Канада"),
]
FLAG_RE = re.compile(r"^[\U0001F1E6-\U0001F1FF]{2}")

# Exact writable configuration fields from the v3.11.0 Inbound model.
# Do not send up/down, clientStats, originNodeGuid, fallbackParent, etc.
FIELDS = (
    "id", "total", "remark", "subSortIndex", "excludeFromSub", "enable",
    "expiryTime", "trafficReset", "trafficResetDay", "listen", "port",
    "protocol", "settings", "streamSettings", "tag", "sniffing",
    "shareAddrStrategy", "shareAddr", "disableFlow",
)


def heading(value):
    print("\n" + "=" * 66 + "\n" + value + "\n" + "=" * 66)


def yes_no(question):
    while True:
        s = input(f"{question} [д/Н]: ").strip().lower()
        if s in ("д", "да", "y", "yes"):
            return True
        if s in ("", "н", "нет", "n", "no", "0"):
            return False
        print("Введите д или н.")


class Debug:
    """Diagnostics without secrets. Never log Authorization or response JSON."""

    def __init__(self, enabled=False, filename=None):
        self.enabled = enabled or bool(filename)
        self.filename = filename
        if filename:
            p = Path(filename)
            p.parent.mkdir(parents=True, exist_ok=True)
            fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            os.close(fd)
            os.chmod(p, 0o600)

    def log(self, message):
        if not self.enabled:
            return
        line = f"[DEBUG {datetime.now().astimezone().isoformat(timespec='seconds')}] {message}"
        print(line, file=sys.stderr)
        if self.filename:
            # Append as text only; never include token, full config or UUIDs.
            with open(self.filename, "a", encoding="utf-8") as f:
                f.write(line + "\n")


def cli(debug, *args):
    """Call panel binary, not /usr/bin/x-ui (the management shell menu)."""
    debug.log("CLI: x-ui " + " ".join(args))
    result = subprocess.run([BINARY, *args], text=True,
                            capture_output=True, timeout=30, check=False)
    if result.returncode:
        raise RuntimeError(f"CLI завершилась с кодом {result.returncode}: "
                           f"{result.stderr[:300]}")
    return result.stdout


def detect_panel(debug):
    """Get transport and secret path dynamically from the official CLI."""
    heading("Настройки локальной панели")
    version = cli(debug, "-v").strip()
    if version.lstrip("v") != "3.11.0":
        raise RuntimeError(f"Версия {version!r} не проверена; ожидается 3.11.0")
    output = cli(debug, "setting", "-show")
    port = re.search(r"(?m)^\s*port:\s*(\d+)\s*$", output)
    path = re.search(r"(?m)^\s*webBasePath:\s*(\S*)\s*$", output)
    if not port or not path:
        raise RuntimeError("Не получены port/webBasePath из CLI")
    port = int(port.group(1))
    if not 1 <= port <= 65535:
        raise RuntimeError("Порт панели вне диапазона")
    basepath = "/" + path.group(1).strip("/") + "/"
    if "Warning: Panel is not secure with SSL" in output:
        scheme = "http"
    elif "Panel is secure with SSL" in output:
        scheme = "https"
    else:
        raise RuntimeError("Не удалось определить HTTP или HTTPS")
    base = f"{scheme}://127.0.0.1:{port}{basepath}"
    print(f"Версия: {version}, протокол: {scheme.upper()}, порт: {port}")
    print(f"Base Path: {basepath}")
    debug.log(f"Подключение к loopback 127.0.0.1:{port}; path скрыт")
    return base, port, scheme


def service_environment():
    """Load only non-secret DB location/type overrides from x-ui env files."""
    result = {}
    for filename in ("/etc/default/x-ui", "/etc/conf.d/x-ui", "/etc/sysconfig/x-ui"):
        if not Path(filename).is_file():
            continue
        try:
            for line in Path(filename).read_text(encoding="utf-8").splitlines():
                m = re.fullmatch(r'\s*(?:export\s+)?(XUI_DB_FOLDER|XUI_DB_TYPE)\s*=\s*(.*?)\s*', line)
                if m:
                    result[m.group(1)] = m.group(2).strip().strip('"\'')
        except OSError:
            pass
        break
    for name in ("XUI_DB_FOLDER", "XUI_DB_TYPE"):
        if name in os.environ:
            result[name] = os.environ[name]
    return result


def read_web_domain(debug):
    """Read *only* webDomain (not inbounds) from SQLite in read-only mode.

    CLI -show does NOT include webDomain; when present, 3x-ui rejects any
    request whose HTTP Host differs. For PostgreSQL, supply --host manually.
    """
    env = service_environment()
    if env.get("XUI_DB_TYPE", "sqlite").lower() in ("postgres", "postgresql", "pg"):
        debug.log("PostgreSQL: чтение webDomain из SQLite пропущено")
        return None
    db = Path(env.get("XUI_DB_FOLDER") or "/etc/x-ui") / "x-ui.db"
    if not db.is_file():
        debug.log("SQLite не найдена в ожидаемом каталоге")
        return None
    try:
        conn = sqlite3.connect(db.resolve().as_uri() + "?mode=ro", uri=True, timeout=3)
        try:
            row = conn.execute("SELECT value FROM settings WHERE key = ? ORDER BY id DESC LIMIT 1",
                               ("webDomain",)).fetchone()
        finally:
            conn.close()
    except sqlite3.Error as e:
        debug.log(f"Не удалось прочитать webDomain в режиме read-only: {type(e).__name__}")
        return None
    web_domain = str(row[0]).strip() if row and row[0] else ""
    debug.log("Listen Domain: " + (web_domain if web_domain else "не задан"))
    return web_domain


def get_token(debug):
    """Rotate ONLY our dedicated admin token; do not persist plaintext."""
    output = cli(debug, "setting", "-getApiToken", "-tokenName", TOKEN_NAME,
                 "-tokenScope", "admin")
    match = re.search(r"(?m)^\s*apiToken:\s*(\S+)\s*$", output)
    if not match:
        raise RuntimeError("CLI не вернула apiToken")
    token = match.group(1)
    debug.log(f"CLI выпустила токен {TOKEN_NAME} с областью admin, длина={len(token)}; значение скрыто")
    return token


class API:
    """Bearer API over loopback; Host may be the configured Listen Domain."""
    def __init__(self, base, token, host, debug):
        self.root = base + "panel/api/inbounds/"
        self.token = token
        self.host = host or None
        self.debug = debug
        # SSL verification is disabled ONLY for this 127.0.0.1 connection;
        # certificates often belong to the public domain, not loopback.
        self.opener = build_opener(
            ProxyHandler({}),
            HTTPSHandler(context=ssl._create_unverified_context()),
        )

    def call(self, method, endpoint, payload=None):
        data = None
        headers = {"Authorization": "Bearer " + self.token,
                   "Accept": "application/json"}
        if self.host:
            headers["Host"] = self.host  # TCP still goes to 127.0.0.1.
        if payload is not None:
            data = json.dumps(payload, ensure_ascii=False, allow_nan=False,
                              separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = Request(self.root + endpoint, headers=headers,
                          data=data, method=method)
        self.debug.log(f"HTTP {method} /panel/api/inbounds/{endpoint} "
                       f"Host={self.host or '127.0.0.1'} payload_bytes={len(data) if data else 0}")
        started = time.monotonic()
        try:
            with self.opener.open(request, timeout=25) as response:
                status = response.status
                result = json.load(response)
        except HTTPError as error:
            # Не выводить тело ответа: в нём могут оказаться секреты.
            self.debug.log(f"HTTP {error.code} за {time.monotonic()-started:.2f}с; "
                           f"тип={error.headers.get('Content-Type','?')}; тело скрыто")
            if error.code == 403:
                raise RuntimeError("HTTP 403: возможное несовпадение Listen Domain "
                                   "(заголовка Host). Запустите с --debug; "
                                   "при необходимости укажите --host ДОМЕН") from error
            if error.code in (401, 404):
                raise RuntimeError(f"HTTP {error.code}: проверьте токен и путь панели") from error
            raise RuntimeError(f"HTTP {error.code}: ошибка API (тело скрыто)") from error
        except (URLError, TimeoutError, OSError, json.JSONDecodeError) as error:
            self.debug.log(f"Сетевая/JSON ошибка: {type(error).__name__}: {str(error)[:200]}")
            raise RuntimeError(f"Сбой API: {type(error).__name__}") from error
        self.debug.log(f"HTTP {status} за {time.monotonic()-started:.2f}с, "
                       f"success={result.get('success') if isinstance(result,dict) else 'wrong-shape'}")
        if not isinstance(result, dict) or result.get("success") is not True:
            raise RuntimeError("API вернула ошибку: " + str(result.get("msg", "?"))[:160])
        return result.get("obj")

    def all(self):
        obj = self.call("GET", "list")
        if not isinstance(obj, list):
            raise RuntimeError("API /list вернула не список")
        return obj

    def one(self, inbound_id):
        return self.call("GET", f"get/{inbound_id}")

    def update(self, inbound_id, payload):
        return self.call("POST", f"update/{inbound_id}", payload)


def is_local(item):
    """Определить физически локальный Inbound, не затронув удалённые узлы.

    В 3x-ui v3.11.0 единственный надёжный признак привязки к узлу — nodeId.
    Для локальных записей поле nodeId отсутствует (omitempty) или равно null.
    originNodeGuid здесь НЕ подходит: GET /list проставляет GUID самой
    панели также и локальным подключениям (annotateLocalOriginGuid).
    """
    return isinstance(item, dict) and item.get("nodeId") is None


def validate(item, inbound_id):
    if not isinstance(item, dict) or item.get("id") != inbound_id or not is_local(item):
        raise RuntimeError(f"ID {inbound_id}: запись не локальная либо некорректна")
    missing = set(FIELDS) - set(item)
    if missing:
        raise RuntimeError(f"ID {inbound_id}: в GET отсутствуют поля {sorted(missing)}")
    if not isinstance(item["remark"], str) or not isinstance(item["shareAddr"], str):
        raise RuntimeError(f"ID {inbound_id}: неверные типы имени/адреса")
    # JSON settings may be objects (v3.11.0 API), arrays or strings (legacy).
    for key in ("settings", "streamSettings", "sniffing"):
        if not isinstance(item[key], (dict, list, str, type(None))):
            raise RuntimeError(f"ID {inbound_id}: неверный тип {key}")


def settings_dict(value):
    """Разобрать settings для проверки риска; конфигурацию НЕ изменять.

    В v3.11.0 JSON чаще приходит как объект, но поддерживаются строки
    старого формата. Для неизвестного типа возвращаем None.
    """
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            decoded = json.loads(value)
            return decoded if isinstance(decoded, dict) else None
        except (ValueError, TypeError):
            return None
    return None


def update_risk(item):
    """Консервативные исключения для полной операции /update/:id.

    Документированная проблема 3x-ui v3.11.0 (#7001): VLESS с реальным
    settings.decryption и fallbacks (даже []) может уронить весь Xray.
    Такое подключение пропускаем, не исправляя конфигурацию автоматически.

    MTProto сервис принудительно нормализует адресную стратегию в 'listen'
    и очищает shareAddr при любой операции update. Если исходные значения
    отличаются, нельзя обещать, что изменится только remark.

    Также сервер нормализует trafficResetDay (0 -> 1) и subSortIndex
    (0 -> 1). Пропускаем такие записи для сохранения неизменности полей.
    """
    protocol = str(item.get("protocol", "")).lower()
    if protocol == "vless":
        settings = settings_dict(item.get("settings"))
        if settings is None:
            return "VLESS: невозможно проверить settings"
        decryption = settings.get("decryption")
        if decryption is not None and str(decryption).strip().lower() not in ("", "none"):
            # Строгая страховка: даже без fallbacks в settings правила
            # fallback могут быть добавлены панелью отдельно.
            return "VLESS encryption: обновление опасно в v3.11.0 (#7001)"
    if protocol == "mtproto":
        if item.get("shareAddrStrategy") != "listen" or item.get("shareAddr") != "":
            return "MTProto: update мог бы изменить стратегию/адрес"
    if item.get("trafficResetDay") == 0:
        return "trafficResetDay=0: API нормализует значение при update"
    if item.get("subSortIndex") == 0:
        return "subSortIndex=0: API нормализует значение при update"
    return None


def flag(code):
    code = code.upper()
    if not re.fullmatch(r"[A-Z]{2}", code):
        raise ValueError("Нужен двухбуквенный код страны")
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in code)


def choose_flag():
    heading("Операция 1: выбор флага (0 — пропустить полностью)")
    print("0) Пропустить")
    for i, (code, country) in enumerate(COUNTRIES, 1):
        print(f"{i:2}) {flag(code)} {country}")
    print("99) Другая страна (двухбуквенный код ISO)")
    while True:
        choice = input("Выберите пункт [0]: ").strip() or "0"
        if choice == "0":
            return None
        if choice == "99":
            try:
                return flag(input("Код страны: ").strip())
            except ValueError as error:
                print(error)
                continue
        if choice.isdecimal() and 1 <= int(choice) <= len(COUNTRIES):
            return flag(COUNTRIES[int(choice)-1][0])
        print("Нет такого пункта")


def valid_public_ipv4(raw):
    try:
        ip = ipaddress.ip_address(str(raw).strip())
        if isinstance(ip, ipaddress.IPv4Address) and ip.is_global:
            return str(ip)
    except ValueError:
        pass
    return None


def detect_ip(debug):
    """Use two independent HTTPS sources; never guess the public IPv4."""
    opener = build_opener(ProxyHandler({}))
    ips = []
    for url in ("https://api.ipify.org", "https://ipv4.icanhazip.com"):
        try:
            req = Request(url, headers={"User-Agent": "xui-local-maint/2.0"})
            with opener.open(req, timeout=7) as response:
                raw = response.read(100).decode("ascii").strip()
            ip = valid_public_ipv4(raw)
            if not ip:
                raise ValueError("ответ не является публичным IPv4")
            ips.append(ip)
            print(f"  {url}: {ip}")
        except (URLError, OSError, ValueError, UnicodeError) as error:
            print(f"  {url}: не получен ({type(error).__name__})")
            debug.log(f"IP probe {url}: {type(error).__name__}")
    if len(ips) == 2 and ips[0] == ips[1]:
        return ips[0]
    print("Автоматически подтвердить IPv4 не удалось.")
    return None


def choose_ip(debug):
    heading("Операция 2: IPv4 для ссылок (стратегию не изменяем)")
    if not yes_no("Обновлять IPv4 в локальных Inbound?"):
        return None
    detected = detect_ip(debug)
    while True:
        value = input(f"IPv4 [{detected or 'введите вручную'}] (0 — пропустить): ").strip()
        if value == "0":
            return None
        ipv4 = valid_public_ipv4(value or detected or "")
        if ipv4:
            return ipv4
        print("Требуется публичный IPv4")


def plan(records, new_flag, new_ip):
    """Планировать только разрешённые поля только локальных подключений.

    Отбор по nodeId уже сделан, но здесь повторяем проверку защиты.
    Возвращает отдельно изменения флага, IP и причины пропуска.
    """
    fc, ic, skip, unsafe = {}, {}, [], []
    for inbound_id, item in records.items():
        if not is_local(item):
            raise RuntimeError(f"ID {inbound_id}: обнаружен удалённый Inbound")
        reason = update_risk(item)
        if reason:
            unsafe.append((inbound_id, reason))
            continue
        if new_flag is not None:
            match = FLAG_RE.match(item["remark"])
            if match:
                new = new_flag + item["remark"][match.end():]
                if new != item["remark"]:
                    fc[inbound_id] = new
        if new_ip is not None:
            if item["protocol"] == "mtproto":
                skip.append((inbound_id, "MTProto: адрес не поддерживается"))
                continue
            if item["shareAddrStrategy"] != "custom":
                skip.append((inbound_id, "стратегия не Пользовательская"))
                continue
            old = item["shareAddr"]
            if old == new_ip:
                continue
            try:
                # Только пустое поле или литеральный IPv4: домены и
                # IPv6 ни при каких условиях не перезаписываем.
                if old and not isinstance(ipaddress.ip_address(old), ipaddress.IPv4Address):
                    skip.append((inbound_id, "указан IPv6"))
                    continue
            except ValueError:
                skip.append((inbound_id, "указан домен/нестандартный адрес"))
                continue
            ic[inbound_id] = new_ip
    return fc, ic, skip, unsafe


def print_preview(title, entries, records, field, count):
    heading(title)
    if not entries:
        print("Изменений нет")
    for inbound_id, new in sorted(entries.items()):
        current = records[inbound_id]
        print(f"ID {inbound_id} [{current['remark']}]: "
              f"{current[field] or '(пусто)'} -> {new}")
    print(f"Изменить: {len(entries)} из {count} локальных")


def backup_originals(records, changes):
    """Back up complete API-retrieved configurations with root-only rights."""
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(BACKUP_DIR, 0o700)
    name = "inbounds-" + datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S-%f") + ".json"
    path = BACKUP_DIR / name
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fp:
        json.dump({"createdUTC": datetime.now(timezone.utc).isoformat(),
                   "inbounds": {str(k): records[k] for k in changes}},
                  fp, ensure_ascii=False, indent=2)
    return path


def ensure_not_changed(current, before, inbound_id):
    """Traffic stats may change; the actual configurable fields must not."""
    validate(current, inbound_id)
    for field in FIELDS:
        if current[field] != before[field]:
            raise RuntimeError(f"ID {inbound_id}: поле {field} изменилось другим процессом")
    if current.get("originNodeGuid") != before.get("originNodeGuid"):
        raise RuntimeError("Изменился источник Inbound")


def apply(api, records, changes, debug):
    backup = backup_originals(records, changes)
    print(f"\nРезервная копия: {backup}")
    # Do not send read-only counters and derived API fields to /update.
    for n, inbound_id in enumerate(sorted(changes), 1):
        original = records[inbound_id]
        current = api.one(inbound_id)
        ensure_not_changed(current, original, inbound_id)
        risk = update_risk(current)
        if risk:
            raise RuntimeError(f"ID {inbound_id}: новая проверка безопасности: {risk}")
        modifications = changes[inbound_id]
        if not set(modifications).issubset({"remark", "shareAddr"}):
            raise RuntimeError("Попытка изменить запрещённое поле")
        if "shareAddr" in modifications and current["shareAddrStrategy"] != "custom":
            raise RuntimeError("Стратегия изменилась: прекращаем обновление")
        body = {key: copy.deepcopy(current[key]) for key in FIELDS}
        body.update(modifications)
        if body["shareAddrStrategy"] != current["shareAddrStrategy"]:
            raise RuntimeError("Запрещено изменять стратегию")
        debug.log(f"ID {inbound_id}: UPDATE только поля {sorted(modifications)}")
        api.update(inbound_id, body)
        actual = api.one(inbound_id)
        validate(actual, inbound_id)
        for field in FIELDS:
            expected = modifications.get(field, current[field])
            if actual[field] != expected:
                raise RuntimeError(f"ID {inbound_id}: после POST неожиданное значение {field}")
        print(f"OK [{n}/{len(changes)}] ID {inbound_id}: {', '.join(modifications)}")
    print(f"\nУспешно обновлено Inbound: {len(changes)}")


def main():
    args = argparse.ArgumentParser(description="3x-ui v3.11.0 local inbound maintainer")
    args.add_argument("--debug", action="store_true", help="Показывать диагностику HTTP/CLI")
    args.add_argument("--debug-file", nargs="?", const="/root/xui-local-debug.log",
                      help="Сохранять диагностику в файл (0600)")
    args.add_argument("--host", help="Host/Listen Domain панели (если автоопределение невозможно)")
    args.add_argument("--dry-run", action="store_true", help="Запретить любую запись Inbound")
    opts = args.parse_args()
    debug = Debug(opts.debug, opts.debug_file)
    if os.geteuid() != 0:
        raise RuntimeError("Запускайте от root")
    if not Path(BINARY).is_file():
        raise RuntimeError("Не найден /usr/local/x-ui/x-ui")

    heading("3x-ui — обслуживание ЛОКАЛЬНЫХ входящих подключений")
    base, port, scheme = detect_panel(debug)
    web_domain = read_web_domain(debug)
    # Explicit --host has priority, then discovered Listen Domain.
    request_host = opts.host or web_domain or None
    if request_host and ("/" in request_host or "://" in request_host):
        raise RuntimeError("Host должен быть доменом без https:// и пути")
    print("HTTP Host:", request_host or "127.0.0.1 (стандартный)")
    if opts.host:
        debug.log("Host выбран параметром --host")
    elif web_domain is None:
        print("Примечание: Listen Domain автоматически не определён; при 403 используйте --host ДОМЕН")

    heading("Авторизация и проверка API")
    token = get_token(debug)
    api = API(base, token, request_host, debug)
    all_inbounds = api.all()  # Test access BEFORE showing interactive menus.
    records = {}
    remote_count = 0
    local_list_count = 0
    local_with_origin_guid = 0
    for item in all_inbounds:
        if not isinstance(item, dict):
            raise RuntimeError("В /list найден некорректный элемент")
        if not is_local(item):
            remote_count += 1
            continue
        local_list_count += 1
        if item.get("originNodeGuid"):
            local_with_origin_guid += 1
        inbound_id = item.get("id")
        if type(inbound_id) is not int or inbound_id <= 0 or inbound_id in records:
            raise RuntimeError("Неверный/дублирующийся ID")
        full = api.one(inbound_id)
        validate(full, inbound_id)
        # GET /list и GET /get обязаны независимо подтвердить nodeId=null.
        records[inbound_id] = full
        debug.log(f"ID {inbound_id}: локальный по nodeId, протокол={full['protocol']}")
    print(f"API доступен. Локальных: {len(records)}, удалённых пропущено: {remote_count}")
    debug.log(f"Получено {len(all_inbounds)} inbounds: "
              f"nodeId=null/нет: {local_list_count}, "
              f"nodeId задан: {remote_count}, "
              f"у локальных заполнен originNodeGuid: {local_with_origin_guid}")
    # Ошибка структуры API или панели не должна давать вводящее в
    # заблуждение меню и тем более запускать операции без локальных записей.
    if not records:
        print("Локальных Inbound нет по признаку nodeId. "
              "Изменений не будет; при необходимости проверьте API с --debug.")
        return

    new_flag = choose_flag()
    new_ip = choose_ip(debug)
    if new_flag is None and new_ip is None:
        print("\nОбе операции пропущены. Изменений нет")
        return

    flag_changes, ip_changes, skipped, unsafe = plan(records, new_flag, new_ip)
    if unsafe:
        heading("Пропущены по проверкам безопасности")
        for inbound_id, reason in unsafe:
            print(f"  ID {inbound_id}: {reason}")
    if new_flag:
        print_preview("Предпросмотр флагов", flag_changes, records, "remark", len(records))
    if new_ip:
        print_preview("Предпросмотр IPv4 (только стратегия custom)",
                      ip_changes, records, "shareAddr", len(records))
        if skipped:
            print("Не будут обновлены по IPv4:")
            for inbound_id, reason in skipped:
                print(f"  ID {inbound_id}: {reason}")

    use_flags = bool(flag_changes) and yes_no("Применить флаги?")
    use_ip = bool(ip_changes) and yes_no("Применить IPv4?")
    changes = {}
    if use_flags:
        for k, v in flag_changes.items():
            changes.setdefault(k, {})["remark"] = v
    if use_ip:
        for k, v in ip_changes.items():
            changes.setdefault(k, {})["shareAddr"] = v
    if not changes:
        print("\nИзменений нет")
        return

    heading("Итог")
    print(f"Флагов: {len(flag_changes) if use_flags else 0}")
    print(f"IPv4: {len(ip_changes) if use_ip else 0}")
    print(f"Уникальных Inbound на обновление: {len(changes)}")
    print("Стратегия адреса НЕ меняется. Удалённые серверы НЕ затрагиваются.")
    print("Проблемные VLESS/MTProto конфигурации отфильтрованы; см. причины выше.")
    if opts.dry_run:
        print("--dry-run: все изменения отменены, запросов POST не будет")
        return
    if not yes_no("Выполнить API POST? Возможна переинициализация Xray"):
        print("Отменено")
        return
    apply(api, records, changes, debug)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nОстановлено пользователем", file=sys.stderr)
        sys.exit(130)
    except Exception as error:
        print("\nОШИБКА:", error, file=sys.stderr)
        print("Если были POST-запросы, проверьте состояние панели и резервную копию.",
              file=sys.stderr)
        sys.exit(1)

"""
Собирает конфиги из публичных источников, отсеивает мусор и публикует лучшее.

Запускается в GitHub Actions по расписанию — не на телефоне пользователя. Это принципиально:
проверка означает реальные соединения, а проверять сотни серверов с телефона значит сжигать
чужой трафик и батарею. Здесь то же самое ничего не стоит.

Что делает, по порядку:
  1. качает все источники из sources.txt;
  2. вытаскивает ссылки на конфиги из любого формата (текст, base64, JSON);
  3. схлопывает дубликаты — по сути конфига, а не по строке;
  4. выбрасывает то, что ядро приложения всё равно не запустит;
  5. проверяет доступность (TCP);
  6. определяет страну по IP пакетными запросами;
  7. отбирает лучших по стране и пишет configs/best.txt.

Замер реальной скорости — следующий шаг, он появится здесь после того, как заработает этот.
Сознательно не тащу два новых механизма в один заход: когда что-то сломается, будет непонятно,
что именно.
"""

from __future__ import annotations

import base64
import binascii
import json
import os
import re
import socket
import sys
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

SOURCES_FILE = "sources.txt"
OUTPUT_FILE = "configs/best.txt"
OUTPUT_META = "configs/best.json"

# Сколько серверов оставлять на страну. Балансировщику в приложении нужно несколько живых
# кандидатов, чтобы было куда переключиться, а не весь список: каждый лишний участник — это
# ещё одна периодическая проверка с телефона.
PER_COUNTRY_LIMIT = 8

# Общий потолок, чтобы разросшийся источник не превратил список в неюзабельный.
TOTAL_LIMIT = 200

FETCH_TIMEOUT = 20
TCP_TIMEOUT = 1.5
TCP_WORKERS = 100

# Схемы, которые приложение умеет. TUIC отсутствует намеренно — в приложении он отключён,
# такие ссылки всё равно были бы отброшены при импорте.
SCHEMES = ("vless://", "trojan://", "ss://", "vmess://", "hysteria2://", "hy2://")

# Работают поверх QUIC, то есть по UDP. TCP-проверка на них всегда провалится — не потому что
# сервер мёртв, а потому что проверять нечего. Пропускаем их через первый этап без проверки.
UDP_SCHEMES = ("hysteria2://", "hy2://")

CONFIG_RE = re.compile(r"(?:" + "|".join(re.escape(s) for s in SCHEMES) + r")[^\s\"'<>\\]+")

# Отпечаток клиента (fp) на работу сервера не влияет — только на то, насколько соединение похоже
# на браузерное. chrome самый массовый, поэтому и распознают его чаще; при выборе представителя
# из группы одинаковых конфигов он идёт последним.
FP_PREFERENCE = ["firefox", "qq", "safari", "ios", "edge", "android", "chrome"]

ISO_TO_RU = {
    "RU": "Россия", "NL": "Нидерланды", "DE": "Германия", "FI": "Финляндия", "FR": "Франция",
    "SE": "Швеция", "PL": "Польша", "CZ": "Чехия", "TR": "Турция", "GB": "Великобритания",
    "US": "США", "CA": "Канада", "JP": "Япония", "SG": "Сингапур", "HK": "Гонконг",
    "KZ": "Казахстан", "AM": "Армения", "LV": "Латвия", "LT": "Литва", "EE": "Эстония",
    "CH": "Швейцария", "AT": "Австрия", "IT": "Италия", "ES": "Испания", "NO": "Норвегия",
    "DK": "Дания", "BE": "Бельгия", "IE": "Ирландия", "MD": "Молдова", "UA": "Украина",
    "BG": "Болгария", "RO": "Румыния", "RS": "Сербия", "HU": "Венгрия", "AE": "ОАЭ",
    "IN": "Индия", "KR": "Южная Корея", "AU": "Австралия", "BR": "Бразилия", "IL": "Израиль",
    "CN": "Китай", "LU": "Люксембург", "PT": "Португалия", "GR": "Греция", "SK": "Словакия",
    "SI": "Словения", "HR": "Хорватия", "IS": "Исландия", "CY": "Кипр", "GE": "Грузия",
    "AZ": "Азербайджан", "UZ": "Узбекистан", "BY": "Беларусь", "TW": "Тайвань",
    "VN": "Вьетнам", "ID": "Индонезия", "TH": "Таиланд", "PH": "Филиппины", "MY": "Малайзия",
}

KEEP_WHITELIST = re.compile(r"(%5B%2ACIDR%5D|\[\*CIDR\]|%5BWL%5D|\[WL\])", re.I)
KEEP_BLACKLIST = re.compile(r"(%5BBL%5D|\[BL\])", re.I)


@dataclass
class Config:
    raw: str
    scheme: str
    host: str
    port: int
    params: dict = field(default_factory=dict)
    latency_ms: int = -1
    country: str = ""


def log(message: str) -> None:
    print(message, flush=True)


# --------------------------------------------------------------------------------------
# 1. Источники
# --------------------------------------------------------------------------------------

def read_sources() -> list[tuple[str, re.Pattern | None]]:
    sources = []
    with open(SOURCES_FILE, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = line.split("|")
            url = parts[0].strip()
            tag = parts[1].strip().upper() if len(parts) > 1 else ""
            keep = KEEP_WHITELIST if tag == "WL" else KEEP_BLACKLIST if tag == "BL" else None
            sources.append((url, keep))
    return sources


def fetch(url: str) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": "config-collector/1"})
    with urllib.request.urlopen(request, timeout=FETCH_TIMEOUT) as response:
        return response.read().decode("utf-8", errors="replace")


def extract_configs(body: str, keep: re.Pattern | None) -> list[str]:
    """
    Вытаскивает ссылки регулярным выражением, а не разбором по строкам.

    Источники приходят в разном виде: обычный текст, base64, JSON с полями. Разбор по строкам
    ломается на каждом новом формате, а поиск по образцу работает со всеми сразу — в том числе
    с keys.json от tiagorrg, где ссылки лежат внутри JSON-полей.
    """
    candidates = CONFIG_RE.findall(body)
    if not candidates:
        # Похоже на base64 — попробуем раскодировать целиком.
        try:
            padded = body.strip() + "=" * (-len(body.strip()) % 4)
            decoded = base64.b64decode(padded).decode("utf-8", errors="replace")
            candidates = CONFIG_RE.findall(decoded)
        except (binascii.Error, ValueError):
            candidates = []
    if keep is not None:
        candidates = [c for c in candidates if keep.search(c)]
    return candidates


# --------------------------------------------------------------------------------------
# 2. Разбор и дедупликация
# --------------------------------------------------------------------------------------

def parse(raw: str) -> Config | None:
    try:
        scheme = next(s for s in SCHEMES if raw.startswith(s))
        rest = raw[len(scheme):]
        # Имя после решётки нам не нужно: мы его всё равно перепишем.
        rest = rest.split("#", 1)[0]
        userinfo, _, hostpart = rest.rpartition("@")
        if not hostpart:
            return None
        hostport, _, query = hostpart.partition("?")
        hostport = hostport.rstrip("/")
        if hostport.startswith("["):  # IPv6 в скобках
            host, _, port_str = hostport.rpartition("]:")
            host = host.lstrip("[")
        else:
            host, _, port_str = hostport.rpartition(":")
        port = int(port_str)
        if not host or not 1 <= port <= 65535:
            return None
        params = {k: v[0] for k, v in urllib.parse.parse_qs(query, keep_blank_values=True).items()}
        return Config(raw=raw, scheme=scheme, host=host, port=port, params=params)
    except Exception:
        return None


def canonical_key(config: Config) -> tuple:
    """
    Что делает конфиг «тем же самым».

    Осознанно не включает fp, имя и spx: в публичных списках один сервер лежит десятком копий,
    отличающихся только отпечатком клиента. Схлопывание таких групп сокращает список в разы и
    ровно на столько же — объём проверок.
    """
    p = config.params
    return (
        config.scheme,
        config.host.lower(),
        config.port,
        p.get("security", ""),
        p.get("sni", ""),
        p.get("pbk", ""),
        p.get("sid", ""),
        p.get("type", ""),
        p.get("path", "") or p.get("serviceName", ""),
        p.get("host", ""),
        p.get("flow", ""),
    )


def fp_rank(config: Config) -> int:
    fp = config.params.get("fp", "").lower()
    return FP_PREFERENCE.index(fp) if fp in FP_PREFERENCE else len(FP_PREFERENCE)


def supported_by_core(config: Config) -> bool:
    """
    Повторяет правила ядра приложения. Каждое из них было найдено на живых ошибках: конфиг,
    который ядро отказывается собрать, ломает не сам себя, а всё подключение целиком.
    """
    p = config.params
    if p.get("allowInsecure") == "1" or p.get("insecure") == "1":
        return False

    security = (p.get("security") or "").lower()
    has_tls = security not in ("", "none")

    if config.scheme == "trojan://":
        return has_tls  # у Trojan своего шифрования нет
    if config.scheme == "vless://":
        encryption = (p.get("encryption") or "").lower()
        return has_tls or encryption not in ("", "none")
    return True


# --------------------------------------------------------------------------------------
# 3. Проверка доступности
# --------------------------------------------------------------------------------------

def tcp_latency(host: str, port: int) -> int:
    import time
    start = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=TCP_TIMEOUT):
            return int((time.monotonic() - start) * 1000)
    except Exception:
        return -1


def check_all(configs: list[Config]) -> None:
    """
    Проверяет каждый уникальный адрес один раз: в этих списках на один адрес приходится по
    несколько конфигов, и повторные проверки того же хоста ничего не добавляют.
    """
    endpoints = {(c.host, c.port) for c in configs if not c.scheme.startswith(UDP_SCHEMES)}
    log(f"TCP-проверка: {len(endpoints)} уникальных адресов")

    with ThreadPoolExecutor(max_workers=TCP_WORKERS) as pool:
        results = dict(zip(endpoints, pool.map(lambda e: tcp_latency(*e), endpoints)))

    for config in configs:
        if config.scheme.startswith(UDP_SCHEMES):
            # Пропускаем вперёд, но с заведомо худшей оценкой: без реального теста мы не знаем,
            # живы ли они, и не должны ставить их выше проверенных.
            config.latency_ms = 9999
        else:
            config.latency_ms = results.get((config.host, config.port), -1)


# --------------------------------------------------------------------------------------
# 4. Страна по IP
# --------------------------------------------------------------------------------------

def resolve_countries(configs: list[Config]) -> None:
    """
    Пакетными запросами: сто адресов за одно обращение вместо ста обращений. На телефоне мы
    упирались в лимит запросов у бесплатного сервиса; здесь этой проблемы нет.
    """
    hosts = sorted({c.host for c in configs})
    mapping: dict[str, str] = {}

    for chunk_start in range(0, len(hosts), 100):
        chunk = hosts[chunk_start:chunk_start + 100]
        payload = json.dumps([{"query": h, "fields": "status,countryCode,query"} for h in chunk])
        try:
            request = urllib.request.Request(
                "http://ip-api.com/batch",
                data=payload.encode(),
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(request, timeout=FETCH_TIMEOUT) as response:
                for entry in json.loads(response.read()):
                    if entry.get("status") == "success":
                        iso = (entry.get("countryCode") or "").upper()
                        if iso in ISO_TO_RU:
                            mapping[entry.get("query", "")] = ISO_TO_RU[iso]
        except Exception as error:
            log(f"Определение страны не удалось для пакета: {error}")

    for config in configs:
        config.country = mapping.get(config.host, "")

    log(f"Страна определена для {sum(1 for c in configs if c.country)} из {len(configs)}")


# --------------------------------------------------------------------------------------
# 5. Отбор и публикация
# --------------------------------------------------------------------------------------

def rename(raw: str, name: str) -> str:
    """Имена задаются здесь, чтобы приложению не приходилось ничего выяснять по сети."""
    base = raw.split("#", 1)[0]
    return f"{base}#{urllib.parse.quote(name)}"


def select(configs: list[Config]) -> list[Config]:
    alive = [c for c in configs if c.latency_ms >= 0 and c.country]
    alive.sort(key=lambda c: c.latency_ms)

    per_country: dict[str, int] = {}
    chosen: list[Config] = []
    for config in alive:
        count = per_country.get(config.country, 0)
        if count >= PER_COUNTRY_LIMIT:
            continue
        per_country[config.country] = count + 1
        chosen.append(config)
        if len(chosen) >= TOTAL_LIMIT:
            break
    return chosen


def publish(chosen: list[Config]) -> None:
    os.makedirs("configs", exist_ok=True)

    numbering: dict[str, int] = {}
    lines, meta = [], []
    for config in chosen:
        index = numbering.get(config.country, 0) + 1
        numbering[config.country] = index
        name = f"{config.country} {index}"
        lines.append(rename(config.raw, name))
        meta.append({
            "name": name,
            "host": config.host,
            "port": config.port,
            "protocol": config.scheme.rstrip(":/"),
            "latency_ms": config.latency_ms,
        })

    # Страховка от катастрофы: если прогон почему-то дал горстку конфигов, публиковать это
    # нельзя — приложение заменяет список целиком, и все пользователи разом получат обрубок.
    # Лучше оставить прошлый результат: он вчера работал.
    if not lines:
        log("ОТКАЗ от публикации: ни одного живого конфига. Скорее всего недоступны источники.")
        sys.exit(1)
    if os.path.exists(OUTPUT_FILE):
        previous = sum(1 for line in open(OUTPUT_FILE, encoding="utf-8") if "://" in line)
        if previous >= 20 and len(lines) < previous // 4:
            log(f"ОТКАЗ от публикации: было {previous}, стало {len(lines)}. Оставляем прошлый список.")
            sys.exit(0)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")
    with open(OUTPUT_META, "w", encoding="utf-8") as handle:
        json.dump({"count": len(meta), "servers": meta}, handle, ensure_ascii=False, indent=1)

    by_country = {}
    for item in meta:
        country = item["name"].rsplit(" ", 1)[0]
        by_country[country] = by_country.get(country, 0) + 1
    log(f"Опубликовано {len(lines)}: " + ", ".join(f"{k} {v}" for k, v in sorted(by_country.items())))


def main() -> None:
    raw_configs: list[str] = []
    for url, keep in read_sources():
        try:
            found = extract_configs(fetch(url), keep)
            log(f"{len(found):5d}  {url}")
            raw_configs.extend(found)
        except Exception as error:
            log(f"    -  {url}  ({error})")

    log(f"Всего собрано строк: {len(raw_configs)}")

    parsed = [c for c in (parse(r) for r in set(raw_configs)) if c]
    log(f"Разобрано: {len(parsed)}")

    parsed = [c for c in parsed if supported_by_core(c)]
    log(f"После отсева непригодных для ядра: {len(parsed)}")

    # Из каждой группы одинаковых по сути конфигов оставляем одного, с лучшим отпечатком.
    best_by_key: dict[tuple, Config] = {}
    for config in parsed:
        key = canonical_key(config)
        current = best_by_key.get(key)
        if current is None or fp_rank(config) < fp_rank(current):
            best_by_key[key] = config
    unique = list(best_by_key.values())
    log(f"После схлопывания дубликатов: {len(unique)}")

    check_all(unique)
    log(f"Ответили: {sum(1 for c in unique if c.latency_ms >= 0)}")

    resolve_countries([c for c in unique if c.latency_ms >= 0])
    publish(select(unique))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
import dns.resolver
import os
from netaddr import IPSet, IPNetwork

# 🇷🇺 Публичные российские DNS
DNS_SERVERS = [
    "77.88.8.8",
    "195.46.39.39",
    "193.58.251.251",
    "185.222.222.222",
    "91.239.26.116"
]

DOMAINS_FILE = "domains.txt"
IPV4_FILE = "ipv4.txt"
CIDR_FILE = "cidr.txt"


def load_existing_ips(filename):
    """Загрузить существующие IP из файла"""
    if not os.path.exists(filename):
        return set()
    with open(filename, "r") as f:
        return set(line.strip() for line in f if line.strip())


def resolve_domain(domain: str):
    """Резолвит домен через список DNS"""
    results = set()
    for dns_ip in DNS_SERVERS:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [dns_ip]
        resolver.timeout = 2
        resolver.lifetime = 2
        try:
            answers = resolver.resolve(domain, "A")
            for rdata in answers:
                results.add(rdata.address)
        except Exception:
            pass
    return results


def generate_cidrs(ips: set):
    """Максимальная агрегация CIDR через netaddr"""
    ipset = IPSet(ips)
    return [str(net) for net in ipset.iter_cidrs()]


def main():
    # Загружаем существующие IP
    existing_ips = load_existing_ips(IPV4_FILE)

    # Читаем домены
    try:
        with open(DOMAINS_FILE, "r") as f:
            domains = [d.strip() for d in f if d.strip()]
    except FileNotFoundError:
        print("Файл domains.txt не найден!")
        return

    # Резолв всех доменов
    new_ips = set()
    for domain in domains:
        ips = resolve_domain(domain)
        print(f"[{domain}] → {list(ips)}")
        new_ips.update(ips)

    # Только уникальные новые IP
    unique_new_ips = new_ips - existing_ips

    if unique_new_ips:
        print(f"Новые уникальные IP: {unique_new_ips}")

        # Добавляем новые IP в ipv4.txt
        with open(IPV4_FILE, "a") as f:
            for ip in sorted(unique_new_ips):
                f.write(ip + "\n")

        # Полный набор IP для агрегации
        all_ips = existing_ips.union(unique_new_ips)

        # Генерация оптимизированных CIDR
        cidrs = generate_cidrs(all_ips)
        with open(CIDR_FILE, "w") as f:
            for cidr in cidrs:
                f.write(cidr + "\n")

        print(f"Оптимизированные CIDR: {cidrs}")
    else:
        print("Новых уникальных IP нет.")


if __name__ == "__main__":
    main()

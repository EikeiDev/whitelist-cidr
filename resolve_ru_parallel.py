#!/usr/bin/env python3
import asyncio
import aiodns
import os
from netaddr import IPSet, IPAddress
from datetime import datetime

# 🇷🇺 Публичные российские DNS
DNS_SERVERS = [
    # Yandex.DNS (Базовый)
    "77.88.8.8",
    "77.88.8.1",
    
    # Yandex.DNS (Безопасный)
    "77.88.8.88",
    "77.88.8.2",
    
    # Yandex.DNS (Семейный)
    "77.88.8.7",
    "77.88.8.3",
    
    # AdGuard.DNS
    "94.140.14.14",
    "94.140.15.15",
    
    # SafeDNS
    "195.46.39.39",
    "195.46.39.40",
    
    # SkyDNS
    "193.58.251.251",
    
    # MSK-IX (NSDI)
    "195.208.4.1",
    "195.208.5.1",
    
    # Другие
    "185.222.222.222",
    "91.239.26.116"
]

# --- ИЗМЕНЕНИЕ: Пути стали относительными ---
DOMAINS_FILE = "data/domains.txt"
IPV4_FILE = "data/ipv4.txt"
CIDR_FILE = "data/cidr.txt"
# -----------------------------------------

# Таймаут для каждого DNS-запроса
DNS_TIMEOUT = 1.0

def load_existing_ips(filename):
    if not os.path.exists(filename):
        return set()
    with open(filename, "r") as f:
        return set(line.strip() for line in f if line.strip())

def generate_cidrs(ips):
    ipset = IPSet(ips)
    return [str(net) for net in ipset.iter_cidrs()]

async def resolve_domain(resolver, domain):
    """
    Асинхронно разрешает один домен.
    Возвращает (domain, set_of_ips)
    """
    ips = set()
    try:
        answers = await resolver.query(domain, "A")
        if answers:
            # --- ФИЛЬТР ПРИВАТНЫХ IP ---
            for r in answers:
                try:
                    # Проверяем, что IP-адрес является публичным (global)
                    ip_addr = IPAddress(r.host)
                    if ip_addr.is_global() and not ip_addr.is_multicast():
                        ips.add(r.host)
                    # else:
                    #     print(f"[{domain}] → отфильтрован приватный IP: {r.host}")
                except Exception:
                    pass # Игнорируем, если IP-адрес невалидный
            # --- КОНЕЦ ФИЛЬТРА ---
        return domain, ips
    except aiodns.error.DNSError as e:
        # Игнорируем ошибки (NXDOMAIN, таймауты и т.д.)
        return domain, set()
    except Exception as e:
        return domain, set()

async def main_async(domains):
    """
    Главная асинхронная функция для разрешения списка доменов.
    """
    # Исправленное имя класса
    resolver = aiodns.DNSResolver(timeout=DNS_TIMEOUT)
    resolver.nameservers = DNS_SERVERS

    # Создаем список задач (coroutine) для каждого домена
    tasks = [resolve_domain(resolver, domain) for domain in domains]

    print(f"Запускаем {len(tasks)} асинхронных DNS-запросов...")
    
    # Запускаем ВСЕ задачи одновременно
    results = await asyncio.gather(*tasks, return_exceptions=True)
    
    print("Все задачи завершены, обрабатываем результаты...")

    new_ips = set()
    for res in results:
        if isinstance(res, Exception):
            print(f"Задача упала с ошибкой: {res}")
            continue
        
        domain, ips = res
        if ips:
            new_ips.update(ips)
            print(f"[{domain}] → {list(ips)}")
            
    return new_ips

def main():
    start_time = datetime.now()
    existing_ips = load_existing_ips(IPV4_FILE)

    try:
        with open(DOMAINS_FILE, "r") as f:
            domains = [d.strip() for d in f if d.strip() and d[0] != '#']
    except FileNotFoundError:
        print(f"Файл {DOMAINS_FILE} не найден!")
        return

    # Запускаем асинхронный event loop
    new_ips = asyncio.run(main_async(domains))

    unique_new_ips = new_ips - existing_ips

    if unique_new_ips:
        print(f"\nНовые уникальные IP: {unique_new_ips}")

        with open(IPV4_FILE, "a") as f:
            for ip in sorted(unique_new_ips):
                f.write(ip + "\n")

        all_ips = existing_ips.union(unique_new_ips)
        cidrs = generate_cidrs(all_ips)
        with open(CIDR_FILE, "w") as f:
            for cidr in cidrs:
                f.write(cidr + "\n")

        print(f"Оптимизированные CIDR: {cidrs}")
    else:
        print("\nНовых уникальных IP нет.")
    
    end_time = datetime.now()
    print(f"Время выполнения: {end_time - start_time}")

if __name__ == "__main__":
    main()
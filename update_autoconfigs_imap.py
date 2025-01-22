#!/usr/local/bin/python3

"""
    This script updates "autoconfigs.txt" file with IMAP configurations.
"""

import os
import sys
import threading
import time
import re
import signal
import queue
import requests
import datetime

filename = 'autoconfigs.txt'
autoconfig_url = 'https://autoconfig.thunderbird.net/v1.1/'
threads_counter = 0
jobs_queue = queue.Queue()
results_queue = queue.Queue()

def quit(signum, frame):
    print('Exiting... See ya later. Bye.')
    sys.exit(0)

def fetcher(jobs_queue, results_queue):
    global threads_counter
    while not jobs_queue.empty():
        domain = jobs_queue.get()
        try:
            xml = requests.get(autoconfig_url + domain, timeout=5).text
        except requests.RequestException:
            xml = ''
        imap_host = re.findall(r'<incomingServer type="imap">[\\s\\S]+?<hostname>([\\w.-]+)</hostname>', xml)
        imap_port = re.findall(r'<incomingServer type="imap">[\\s\\S]+?<port>([\\d]+)</port>', xml)
        imap_login_template = re.findall(r'<incomingServer type="imap">[\\s\\S]+?<username>([\\w.%]+)</username>', xml)
        if imap_host and imap_port and imap_login_template:
            results_queue.put((domain, imap_host[0], imap_port[0], imap_login_template[0]))
        jobs_queue.task_done()  # Помечаем задачу как выполненную
    threads_counter -= 1

signal.signal(signal.SIGINT, quit)

# Загружаем список доменов
try:
    domain_list = re.findall(r'<a href="([\\w.-]+)">', requests.get(autoconfig_url, timeout=10).text)
    for domain in domain_list:
        jobs_queue.put(domain)
except requests.RequestException as e:
    print(f"Failed to fetch domain list: {e}")
    sys.exit(1)

# Запускаем потоки для обработки
for _ in range(min(30, jobs_queue.qsize())):
    threading.Thread(target=fetcher, args=(jobs_queue, results_queue), daemon=True).start()
    threads_counter += 1

# Ожидание завершения потоков
while threads_counter > 0:
    time.sleep(0.1)

# Запись результатов в файл
with open(filename, 'w', encoding='utf-8') as fp:
    fp.write('fetched from: ' + autoconfig_url + ', updated at: ' + str(datetime.date.today()) + '\\n')
    fp.write('domain;imap_host:imap_port;imap_login_template\\n')
    while not results_queue.empty():
        domain, imap_host, imap_port, imap_login_template = results_queue.get()
        single_conf_string = f"{domain};{imap_host}:{imap_port};{imap_login_template}"
        fp.write(single_conf_string + '\\n')
        print(single_conf_string)

print("Processing complete.")

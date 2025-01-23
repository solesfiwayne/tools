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
today = datetime.date.today()
jobs_queue = queue.Queue()
results_queue = queue.Queue()

def quit(signum, frame):
    print('Exiting... See ya later. Bye.')
    sys.exit(0)

def fetcher(jobs_queue, results_queue):
    global threads_counter
    while True:
        if jobs_queue.empty():
            break
        domain = jobs_queue.get()
        try:
            xml = requests.get(autoconfig_url + domain, timeout=3).text
        except:
            xml = ''
        
        # Поиск всех доменов в секции <domain>
        domain_list = re.findall(r'<domain>([\w.-]+)</domain>', xml)
        for subdomain in domain_list:
            # Проверка IMAP-конфигурации для каждого домена
            imap_host = re.findall(r'<incomingServer type="imap">[\s\S]+?<hostname>([\w.-]+)</hostname>', xml)
            imap_port = re.findall(r'<incomingServer type="imap">[\s\S]+?<port>([\d]+)</port>', xml)
            imap_login_template = re.findall(r'<incomingServer type="imap">[\s\S]+?<username>([\w.%]+)</username>', xml)
            if imap_host and imap_port and imap_login_template:
                results_queue.put((subdomain, imap_host[0], imap_port[0], imap_login_template[0]))
    time.sleep(1)
    threads_counter -= 1

signal.signal(signal.SIGINT, quit)

# Сканируем основной список доменов с autoconfig URL
domain_list = re.findall(r'<a href="([\w.-]+)">', requests.get(autoconfig_url, timeout=3).text)
for domain in domain_list:
    jobs_queue.put(domain)

# Запуск потоков для обработки
while threads_counter < 30:
    threading.Thread(target=fetcher, args=(jobs_queue, results_queue), daemon=True).start()
    threads_counter += 1

# Запись результатов в файл
with open(filename, 'a') as fp:
    fp.write('fetched from: ' + autoconfig_url + ', updated at: ' + str(datetime.date.today()) + '\n')
    fp.write('domain;imap_host:imap_port;imap_login_template\n')
    while threads_counter > 0:
        if not results_queue.empty():
            single_conf_string = ';'.join(results_queue.get())
            fp.write(single_conf_string + '\n')
            print(single_conf_string)

import os
import sys
import threading
import time
import re
import signal
import queue
import requests
import datetime
from bs4 import BeautifulSoup

filename = 'autoconfigs_imap.txt'
autoconfig_url = 'https://www.getmailbird.com/setup/ru/'
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
            page = requests.get(autoconfig_url + domain, timeout=5).text
            soup = BeautifulSoup(page, 'html.parser')
        except:
            soup = None
        
        if soup:
            imap_host = soup.find(text=re.compile('IMAP Server'))
            imap_port = soup.find(text=re.compile('IMAP Port'))
            imap_login_template = soup.find(text=re.compile('Username'))
            
            if imap_host and imap_port and imap_login_template:
                imap_host = imap_host.find_next('td').text.strip()
                imap_port = imap_port.find_next('td').text.strip()
                imap_login_template = imap_login_template.find_next('td').text.strip()
                results_queue.put((domain, imap_host, imap_port, imap_login_template))
    time.sleep(1)
    threads_counter -= 1

signal.signal(signal.SIGINT, quit)

# Получаем список доменов со страницы Mailbird
domain_list = []
try:
    main_page = requests.get(autoconfig_url, timeout=5).text
    soup = BeautifulSoup(main_page, 'html.parser')
    for link in soup.find_all('a', href=True):
        if '/setup/' in link['href']:
            domain = link['href'].split('/')[-2]
            domain_list.append(domain)
except:
    print("Ошибка при получении списка доменов")

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
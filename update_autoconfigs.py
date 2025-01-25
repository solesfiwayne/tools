#!/usr/local/bin/python3

"""
    This script is intented to run from time to time,
    to update "autoconfigs.txt" file.
    Actually, you can even don't touch it - it's ok.
"""

import os, sys, threading, time, re, signal, queue, requests, datetime

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
        smtp_configs = re.findall(r'<outgoingServer type="smtp">[\s\S]*?<hostname>([\w.-]+)</hostname>[\s\S]*?<port>([\d]+)</port>[\s\S]*?<username>([\w.%]+)</username>', xml)
        for smtp_host, smtp_port, smtp_login_template in smtp_configs:
            results_queue.put((domain, smtp_host, smtp_port, smtp_login_template))
    time.sleep(1)
    threads_counter -= 1

signal.signal(signal.SIGINT, quit)

domain_list = re.findall(r'<a href="([\w.-]+)">', requests.get(autoconfig_url, timeout=3).text)
for domain in domain_list:
    jobs_queue.put(domain)

while threads_counter < 30:
    threading.Thread(target=fetcher, args=(jobs_queue, results_queue), daemon=True).start()
    threads_counter += 1

with open(filename, 'a') as fp:
    fp.write(f'Fetched from: {autoconfig_url}, updated at: {today}\n')
    fp.write('Domain;SMTP Host:SMTP Port:SMTP Login Template\n')
    while threads_counter > 0 or not results_queue.empty():
        if not results_queue.empty():
            domain, smtp_host, smtp_port, smtp_login_template = results_queue.get()
            single_conf_string = f'{domain};{smtp_host}:{smtp_port}:{smtp_login_template}'
            fp.write(single_conf_string + '\n')
            print(single_conf_string)

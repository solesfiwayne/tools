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

MAX_RETRIES = 9  # Максимальное количество повторных попыток
RETRY_DELAY = 2  # Задержка между повторными попытками (в секундах)

def quit(signum, frame):
	print('Exiting... See ya later. Bye.')
	sys.exit(0)

def fetcher(jobs_queue, results_queue):
	global threads_counter
	while True:
		if jobs_queue.empty():
			break
		domain = jobs_queue.get()
		retries = 0
		while retries < MAX_RETRIES:
			try:
				xml = requests.get(autoconfig_url + domain, timeout=3).text
				if xml:
					break
			except requests.RequestException:
				xml = ''
			retries += 1
			if retries < MAX_RETRIES:
				print(f"Retrying {domain} ({retries}/{MAX_RETRIES})...")
				time.sleep(RETRY_DELAY)
		if not xml:
			print(f"Failed to fetch configuration for {domain} after {MAX_RETRIES} attempts.")
			continue
		smtp_host = re.findall(r'<outgoingServer type="smtp">[\s\S]+?<hostname>([\w.-]+)</hostname>', xml)
		smtp_port = re.findall(r'<outgoingServer type="smtp">[\s\S]+?<port>([\d+]+)</port>', xml)
		smtp_login_template = re.findall(r'<outgoingServer type="smtp">[\s\S]+?<username>([\w.%]+)</username>', xml)
		if smtp_host and smtp_port and smtp_login_template:
			results_queue.put((domain, smtp_host[0], smtp_port[0], smtp_login_template[0]))
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
	fp.write('fetched from: '+autoconfig_url+', updated at: '+str(datetime.date.today())+'\n')
	fp.write('domain;smtp_host:smtp_port;smtp_login_template\n')
	while threads_counter > 0 or not results_queue.empty():
		if not results_queue.empty():
			result = results_queue.get()
			single_conf_string = f'{result[0]};{result[1]}:{result[2]}:{result[3]}'
			fp.write(single_conf_string+'\n')
			print(single_conf_string)

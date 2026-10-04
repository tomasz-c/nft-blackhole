#!/usr/bin/env python3

'''Script to blocking IP in nftables by country and black lists'''

__author__ = "Tomasz Cebula <tomasz.cebula@gmail.com>"
__license__ = "MIT"
__version__ = "1.4.0"

import argparse
from sys import stderr, exit
from string import Template
import urllib.request
import ssl
from subprocess import run, DEVNULL
from concurrent.futures import ThreadPoolExecutor, as_completed
from yaml import safe_load
import time
from os.path import exists

desc = 'Daemon blocking IP addresses upon country or blacklist, using nftables'
parser = argparse.ArgumentParser(description=desc)
parser.add_argument('action', choices=('start', 'stop', 'restart', 'reload'),
                    help='Action to nft-blackhole')
args = parser.parse_args()
action = args.action

def stop():
    '''Stopping nft-blackhole'''
    run(['nft', 'delete', 'table', 'inet', 'blackhole'], check=False)

if action == 'stop':
    stop()
    exit(0)

# Get config
config_path = '/etc/nft-blackhole/config.yaml'

# BACKWARD COMPATIBILITY: Legacy configuration file path (/etc/nft-blackhole.conf).
# Remove this block when migrating fully to /etc/nft-blackhole/config.yaml.
legacy_config_path = '/etc/nft-blackhole.conf'
if exists(legacy_config_path):
    print(f'WARNING: Found legacy configuration file {legacy_config_path}. '
          f'Please migrate your settings to {config_path} and remove {legacy_config_path}.', file=stderr)
    config_path = legacy_config_path
# END BACKWARD COMPATIBILITY

try:
    with open(config_path) as cnf:
        config = safe_load(cnf)
except OSError as exc:
    print(f'ERROR: Failed to open configuration file {config_path}: {exc}', file=stderr)
    exit(1)

WHITELIST = config.get('WHITELIST', [])
BLACKLIST = config.get('BLACKLIST', [])
COUNTRY_LIST = config['COUNTRY_LIST']
BLOCK_OUTPUT = config['BLOCK_OUTPUT']
BLOCK_FORWARD = config['BLOCK_FORWARD']
COUNTRY_LIST_SOURCE = config.get('COUNTRY_LIST_SOURCE', 'ipverse')
PRIORITY = config.get('PRIORITY', -1)


# Correct incorrect YAML parsing of NO (Norway)
# It should be the string 'no', but YAML interprets it as False
# This is a hack due to the lack of YAML 1.2 support by PyYAML
while False in COUNTRY_LIST:
    COUNTRY_LIST[COUNTRY_LIST.index(False)] = 'no'

SET_TEMPLATE = ('table inet blackhole {\n\tset ${set_name} {\n\t\ttype ${ip_ver}_addr\n'
                '\t\tflags interval\n\t\tauto-merge\n\t\telements = { ${ip_list} }\n\t}\n}').expandtabs()

FORWARD_TEMPLATE = ('\tchain forward {\n\t\ttype filter hook forward priority ${priority}; policy ${default_policy};\n'
                    '\t\tct state established,related accept\n'
                    '\t\tip saddr @whitelist-v4 counter accept\n'
                    '\t\tip6 saddr @whitelist-v6 counter accept\n'
                    '\t\tip saddr @blacklist-v4 counter ${block_policy}\n'
                    '\t\tip6 saddr @blacklist-v6 counter ${block_policy}\n'
                    '\t\t${country_ex_ports_rule}\n'
                    '\t\tip saddr @country-v4 counter ${country_policy}\n'
                    '\t\tip6 saddr @country-v6 counter ${country_policy}\n'
                    '\t\tcounter\n\t}').expandtabs()

OUTPUT_TEMPLATE = ('\tchain output {\n\t\ttype filter hook output priority ${priority}; policy accept;\n'
                   '\t\tip daddr @whitelist-v4 counter accept\n'
                   '\t\tip6 daddr @whitelist-v6 counter accept\n'
                   '\t\tip daddr @blacklist-v4 counter ${block_policy}\n'
                   '\t\tip6 daddr @blacklist-v6 counter ${block_policy}\n\t}').expandtabs()

COUNTRY_EX_PORTS_TEMPLATE = 'meta l4proto { tcp, udp } th dport { ${country_ex_ports} } counter accept'

IP_VER = []
for ip_v in ['v4', 'v6']:
    if config['IP_VERSION'][ip_v]:
        IP_VER.append(ip_v)

BLOCK_POLICY = 'reject' if config['BLOCK_POLICY'] == 'reject' else 'drop'
COUNTRY_POLICY = 'accept' if config['COUNTRY_POLICY'] == 'accept' else 'block'
COUNTRY_EXCLUDE_PORTS = config['COUNTRY_EXCLUDE_PORTS']

if COUNTRY_POLICY == 'block':
    default_policy = 'accept'
    block_policy = BLOCK_POLICY
    country_policy = BLOCK_POLICY
else:
    default_policy = BLOCK_POLICY
    block_policy = BLOCK_POLICY
    country_policy = 'accept'

if COUNTRY_EXCLUDE_PORTS:
    country_ex_ports = ', '.join(map(str, config['COUNTRY_EXCLUDE_PORTS']))
    country_ex_ports_rule = Template(COUNTRY_EX_PORTS_TEMPLATE).substitute(country_ex_ports=country_ex_ports)
else:
    country_ex_ports_rule = ''

if BLOCK_OUTPUT:
    chain_output = Template(OUTPUT_TEMPLATE).substitute(priority=PRIORITY,
                                                        block_policy=block_policy)
else:
    chain_output = ''

if BLOCK_FORWARD:
    chain_forward = Template(FORWARD_TEMPLATE).substitute(priority=PRIORITY,
                                                          default_policy=default_policy,
                                                          block_policy=block_policy,
                                                          country_policy=country_policy,
                                                          country_ex_ports_rule=country_ex_ports_rule)
else:
    chain_forward = ''

# Setting urllib
ctx = ssl.create_default_context()
IGNORE_CERTIFICATE = False
if IGNORE_CERTIFICATE:
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

https_handler = urllib.request.HTTPSHandler(context=ctx)

opener = urllib.request.build_opener(https_handler)
opener.addheaders = [('User-agent', f"Mozilla/5.0 (compatible; nft-blackhole/{__version__}; "
                      '+https://github.com/tomasz-c/nft-blackhole)')]
urllib.request.install_opener(opener)


def start():
    '''Starting nft-blackhole'''
    nft_template = open('/usr/share/nft-blackhole/nft-blackhole.template').read()
    nft_conf = Template(nft_template).substitute(priority=PRIORITY,
                                                 default_policy=default_policy,
                                                 block_policy=block_policy,
                                                 country_ex_ports_rule=country_ex_ports_rule,
                                                 country_policy=country_policy,
                                                 chain_output=chain_output,
                                                 chain_forward=chain_forward)

    run(['nft', '-f', '-'], input=nft_conf.encode(), check=True)

def get_urls(urls, max_retries=3, retry_delay=5):
    '''Download url in threads with retry logic'''
    ip_list_aggregated = []
    def get_url(url):
        for attempt in range(max_retries):
            try:
                response = urllib.request.urlopen(url, timeout=10)
                content = response.read().decode('utf-8')
            except BaseException as exc:
                if attempt < max_retries - 1:
                    print(f'WARNING: Failed to fetch {url} on attempt {attempt+1}/{max_retries}. Retrying in {retry_delay}s. Error: {exc}', file=stderr)
                    time.sleep(retry_delay)
                    continue
                else:
                    print(f'ERROR: Failed to fetch {url} after {max_retries} attempts. Giving up. Final error: {exc}', file=stderr)
                    return None
            else:
                return content.splitlines()
        return None

    with ThreadPoolExecutor(max_workers=8) as executor:
        do_urls = [executor.submit(get_url, url) for url in urls]
        for out in as_completed(do_urls):
            ip_list = out.result()
            if ip_list is None:
                return None
            ip_list_aggregated += ip_list
    return ip_list_aggregated

def split_ip_versions(ip_list):
    '''Split mixed list into deduplicated IPv4 and IPv6 sets'''
    split_ips = {'v4': set(), 'v6': set()}
    v4_add = split_ips['v4'].add
    v6_add = split_ips['v6'].add

    for line in ip_list:
        if '#' in line:
            line = line.partition('#')[0]
        parts = line.split()
        if not parts:
            continue
        entry = parts[0]
        if ':' in entry:
            v6_add(entry)
        elif '.' in entry:
            v4_add(entry)

    return split_ips


def load_ip_sources(config_entry):
    '''Load IP sources: extract direct IPs, read local files, and fetch URLs, splitting into v4 and v6'''
    if not config_entry:
        return {'v4': set(), 'v6': set()}

    raw_ips = []
    file_paths = []
    urls = []

    def to_list(val):
        if not val:
            return []
        if isinstance(val, list):
            return val
        return [val]

    if isinstance(config_entry, dict):
        if any(k in config_entry for k in ('static', 'file', 'url')):
            raw_ips.extend(to_list(config_entry.get('static')))
            file_paths.extend(to_list(config_entry.get('file')))
            urls.extend(to_list(config_entry.get('url')))
        else:
            # BACKWARD COMPATIBILITY: Legacy dictionary format (v4, v6).
            # Remove this block when migrating fully to static/file/url format.
            for key in ['v4', 'v6']:
                for item in to_list(config_entry.get(key)):
                    item_str = str(item).strip()
                    if item_str.startswith(('http://', 'https://')):
                        urls.append(item_str)
                    else:
                        raw_ips.append(item_str)
            # END BACKWARD COMPATIBILITY
    elif isinstance(config_entry, list):
        # BACKWARD COMPATIBILITY: Flat list format.
        # Remove this block when migrating fully to static/file/url format.
        for item in config_entry:
            if not item:
                continue
            item_str = str(item).strip()
            if item_str.startswith(('http://', 'https://')):
                urls.append(item_str)
            else:
                raw_ips.append(item_str)
        # END BACKWARD COMPATIBILITY

    # Read local files
    for filepath in file_paths:
        if not filepath:
            continue
        filepath = str(filepath).strip()
        if not filepath or filepath.startswith('#'):
            continue
        try:
            with open(filepath, 'r') as f:
                raw_ips.extend(f.readlines())
        except OSError as exc:
            print(f'ERROR: Failed to read local file {filepath}: {exc}', file=stderr)
            return None

    # Fetch URLs
    if urls:
        clean_urls = []
        for u in urls:
            if not u:
                continue
            u_str = str(u).strip()
            if u_str and not u_str.startswith('#'):
                clean_urls.append(u_str)
        if clean_urls:
            unique_urls = list(dict.fromkeys(clean_urls))
            downloaded = get_urls(unique_urls)
            if downloaded is None:
                return None
            raw_ips.extend(downloaded)

    return split_ip_versions(raw_ips)


def get_country_ips():
    '''Fetch country IP lists based on configured source and return dict per IP version'''
    if not COUNTRY_LIST:
        return {'v4': set(), 'v6': set()}

    urls = []
    for ip_ver in IP_VER:
        for country in COUNTRY_LIST:
            c_lower = country.lower()
            if COUNTRY_LIST_SOURCE == 'ebrasha':
                c_upper = country.upper()
                url = f'https://raw.githubusercontent.com/ebrasha/cidr-ip-ranges-by-country/refs/heads/master/CIDR/{c_upper}-ip{ip_ver}-Hackers.Zone.txt'
            elif COUNTRY_LIST_SOURCE == 'ipdeny':
                if ip_ver == 'v4':
                    url = f'https://www.ipdeny.com/ipblocks/data/aggregated/{c_lower}-aggregated.zone'
                else:
                    url = f'https://www.ipdeny.com/ipv6/ipaddresses/aggregated/{c_lower}-aggregated.zone'
            else:  # ipverse
                url = f'https://raw.githubusercontent.com/ipverse/geo-ip-blocks/refs/heads/master/country/{c_lower}/{c_lower}-ip{ip_ver}.txt'
            urls.append(url)

    raw_ips = get_urls(urls)
    if raw_ips is None:
        return None

    return split_ip_versions(raw_ips)

def apply_nft_sets(ip_data, reload=False):
    '''Create all nftables sets (whitelist, blacklist, country)'''
    for set_type in ('whitelist', 'blacklist', 'country'):
        for ip_ver in IP_VER:
            set_name = f'{set_type}-{ip_ver}'
            ip_list = ip_data[set_type][ip_ver]
            set_list = ', '.join(ip_list)
            nft_set = (Template(SET_TEMPLATE).substitute(ip_ver=f'ip{ip_ver}', set_name=set_name, ip_list=set_list))
            if reload:
                run(['nft', 'flush', 'set', 'inet', 'blackhole', set_name], check=False)
            if ip_list:
                run(['nft', '-f', '-'], input=nft_set.encode(), check=True)

def fetch_all_lists():
    '''Fetch all whitelist, blacklist and country lists with validation'''
    whitelist_ips = load_ip_sources(WHITELIST)
    if whitelist_ips is None:
        return None

    blacklist_ips = load_ip_sources(BLACKLIST)
    if blacklist_ips is None:
        return None

    country_ips = get_country_ips()
    if country_ips is None:
        return None
    return {'whitelist': whitelist_ips, 'blacklist': blacklist_ips, 'country': country_ips}

# Main
if action == 'start':
    ip_data = fetch_all_lists()
    if ip_data is None:
        print('ERROR: Failed to fetch lists, aborting start', file=stderr)
        exit(1)
    start()
    apply_nft_sets(ip_data)
elif action == 'restart':
    ip_data = fetch_all_lists()
    if ip_data is None:
        print('ERROR: Failed to fetch lists, cleaning up and aborting restart', file=stderr)
        stop()
        exit(1)
    stop()
    start()
    apply_nft_sets(ip_data)
elif action == 'reload':
    ip_data = fetch_all_lists()
    if ip_data is None:
        print('ERROR: Failed to fetch lists, skipping reload', file=stderr)
        exit(1)
    result = run(['nft', 'list', 'chain', 'inet', 'blackhole', 'input'],
                 stdout=DEVNULL, stderr=DEVNULL, check=False)
    if result.returncode != 0:
        start()
    apply_nft_sets(ip_data, reload=True)

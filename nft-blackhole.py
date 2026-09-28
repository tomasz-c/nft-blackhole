#!/usr/bin/env python3

'''Script to blocking IP in nftables by country and black lists'''

__author__ = "Tomasz Cebula <tomasz.cebula@gmail.com>"
__license__ = "MIT"
__version__ = "1.4.0"

import argparse
from sys import stderr, exit
from string import Template
import re
import urllib.request
import ssl
from subprocess import run, DEVNULL
from concurrent.futures import ThreadPoolExecutor, as_completed
from yaml import safe_load
import time

desc = 'Daemon blocking IP addresses upon country or blacklist, using nftables'
parser = argparse.ArgumentParser(description=desc)
parser.add_argument('action', choices=('start', 'stop', 'restart', 'reload'),
                    help='Action to nft-blackhole')
args = parser.parse_args()
action = args.action

# Get config
with open('/etc/nft-blackhole.conf') as cnf:
    config = safe_load(cnf)

WHITELIST = config['WHITELIST']
BLACKLIST = config['BLACKLIST']
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
# opener.addheaders = [('User-agent', f"Mozilla/5.0 (compatible; nft-blackhole/{__version__};")]
opener.addheaders = [('User-agent', f"Mozilla/5.0 (compatible; nft-blackhole/{__version__}; "
                      '+https://github.com/tomasz-c/nft-blackhole)')]
urllib.request.install_opener(opener)

def stop():
    '''Stopping nft-blackhole'''
    run(['nft', 'delete', 'table', 'inet', 'blackhole'], check=False)


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

def get_urls(urls, do_filter=False, max_retries=3, retry_delay=5):
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
                if do_filter:
                    content = re.sub(r'^\s*(?:#.*)?\n', '', content, flags=re.MULTILINE)
                ip_list = content.splitlines()
                return ip_list
        return None

    with ThreadPoolExecutor(max_workers=8) as executor:
        do_urls = [executor.submit(get_url, url) for url in urls]
        for out in as_completed(do_urls):
            ip_list = out.result()
            if ip_list is None:
                return None
            ip_list_aggregated += ip_list
    return ip_list_aggregated


def get_blacklist(ip_ver):
    '''Get blacklists'''
    urls = []
    for bl_url in BLACKLIST[ip_ver]:
        urls.append(bl_url)
    ips = get_urls(urls, do_filter=True)
    return ips


def get_country_ip_list_ipverse(ip_ver):
    '''Get country lists from GitHub @ipverse'''
    urls = []
    for country in COUNTRY_LIST:
        url = f'https://raw.githubusercontent.com/ipverse/geo-ip-blocks/refs/heads/master/country/{country.lower()}/{country.lower()}-ip{ip_ver}.txt'
        urls.append(url)
    ips = get_urls(urls, do_filter=True)
    return ips


def get_country_ip_list_ebrasha(ip_ver):
    '''Get country lists from GitHub @ipverse'''
    urls = []
    for country in COUNTRY_LIST:
        url = f'https://raw.githubusercontent.com/ebrasha/cidr-ip-ranges-by-country/refs/heads/master/CIDR/{country.upper()}-ip{ip_ver}-Hackers.Zone.txt'
        urls.append(url)
    ips = get_urls(urls, do_filter=True)
    return ips


def get_country_ip_list_ipdeny(ip_ver):
    '''Get country lists from ipdeny.com'''
    urls = []
    for country in COUNTRY_LIST:
        if ip_ver == 'v4':
            url = f'https://www.ipdeny.com/ipblocks/data/aggregated/{country.lower()}-aggregated.zone'
        elif ip_ver == 'v6':
            url = f'https://www.ipdeny.com/ipv6/ipaddresses/aggregated/{country.lower()}-aggregated.zone'
        urls.append(url)
    ips = get_urls(urls)
    return ips


def whitelist_sets(reload=False):
    '''Create whitelist sets'''
    for ip_ver in IP_VER:
        set_name = f'whitelist-{ip_ver}'
        set_list = ', '.join(WHITELIST[ip_ver])
        nft_set = (Template(SET_TEMPLATE).substitute(ip_ver=f'ip{ip_ver}', set_name=set_name, ip_list=set_list))
        if reload:
            run(['nft', 'flush', 'set', 'inet', 'blackhole', set_name], check=False)
        if WHITELIST[ip_ver]:
            run(['nft', '-f', '-'], input=nft_set.encode(), check=True)


def blacklist_sets(ip_data, reload=False):
    '''Create blacklist sets'''
    for ip_ver in IP_VER:
        set_name = f'blacklist-{ip_ver}'
        ip_list = ip_data['blacklist'][ip_ver]
        set_list = ', '.join(ip_list)
        nft_set = (Template(SET_TEMPLATE).substitute(ip_ver=f'ip{ip_ver}', set_name=set_name, ip_list=set_list))
        if reload:
            run(['nft', 'flush', 'set', 'inet', 'blackhole', set_name], check=False)
        if ip_list:
            run(['nft', '-f', '-'], input=nft_set.encode(), check=True)


def country_sets(ip_data, reload=False):
    '''Create country sets'''
    for ip_ver in IP_VER:
        set_name = f'country-{ip_ver}'
        ip_list = ip_data['country'][ip_ver]
        set_list = ', '.join(ip_list)
        nft_set = (Template(SET_TEMPLATE).substitute(ip_ver=f'ip{ip_ver}', set_name=set_name, ip_list=set_list))
        if reload:
            run(['nft', 'flush', 'set', 'inet', 'blackhole', set_name], check=False)
        if ip_list:
            run(['nft', '-f', '-'], input=nft_set.encode(), check=True)


def fetch_all_lists():
    '''Fetch all blacklist and country lists with validation'''
    ip_data = {'blacklist': {}, 'country': {}}

    for ip_ver in IP_VER:
        blacklist_ips = get_blacklist(ip_ver)
        if blacklist_ips is None:
            return None
        ip_data['blacklist'][ip_ver] = blacklist_ips

        if COUNTRY_LIST_SOURCE == 'ebrasha':
            country_ips = get_country_ip_list_ebrasha(ip_ver)
        elif COUNTRY_LIST_SOURCE == 'ipdeny':
            country_ips = get_country_ip_list_ipdeny(ip_ver)
        else:
            country_ips = get_country_ip_list_ipverse(ip_ver)

        if country_ips is None:
            return None
        ip_data['country'][ip_ver] = country_ips

    return ip_data

# Main
if action == 'start':
    ip_data = fetch_all_lists()
    if ip_data is None:
        print('ERROR: Failed to fetch lists, aborting start', file=stderr)
        exit(1)
    start()
    whitelist_sets()
    blacklist_sets(ip_data)
    country_sets(ip_data)
elif action == 'stop':
    stop()
elif action == 'restart':
    ip_data = fetch_all_lists()
    if ip_data is None:
        print('ERROR: Failed to fetch lists, cleaning up and aborting restart', file=stderr)
        stop()
        exit(1)
    stop()
    start()
    whitelist_sets()
    blacklist_sets(ip_data)
    country_sets(ip_data)
elif action == 'reload':
    ip_data = fetch_all_lists()
    if ip_data is None:
        print('ERROR: Failed to fetch lists, skipping reload', file=stderr)
        exit(1)
    result = run(['nft', 'list', 'chain', 'inet', 'blackhole', 'input'],
                 stdout=DEVNULL, stderr=DEVNULL, check=False)
    if result.returncode != 0:
        start()
    whitelist_sets(reload=True)
    blacklist_sets(ip_data, reload=True)
    country_sets(ip_data, reload=True)

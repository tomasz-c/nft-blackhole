#!/bin/python

'''Script to blocking IP in nftables by country and black lists'''

__author__ = "Tomasz Cebula <tomasz.cebula@gmail.com>"
__license__ = "MIT"
__version__ = "0.1.0"

import argparse
from sys import stderr
from string import Template
import re
import urllib.request
import ssl
from subprocess import run
from concurrent.futures import ThreadPoolExecutor, as_completed
from yaml import safe_load

desc = 'Script to blocking IP in nftables by country and black lists'
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

# Correct incorrect YAML parsing of NO (Norway)
# It should be the string 'no', but YAML interprets it as False
while False in COUNTRY_LIST:
    COUNTRY_LIST[COUNTRY_LIST.index(False)] = 'no'

SET_TEMPLATE = ('table inet blackhole {\n\tset ${set_name} {\n\t\ttype ${ip_ver}_addr\n'
                '\t\tflags interval\n\t\tauto-merge\n\t\telements = { ${ip_list} }\n\t}\n}')

IP_VER = []
for ip_v in ['v4', 'v6']:
    if config['IP_VERSION'][ip_v]:
        IP_VER.append(ip_v)

BLOCK_POLICY = 'reject' if config['BLOCK_POLICY'] == 'reject' else 'drop'
COUNTRY_POLICY = 'accept' if config['COUNTRY_POLICY'] == 'accept' else 'block'

if COUNTRY_POLICY == 'block':
    default_policy = 'accept'
    block_policy = BLOCK_POLICY
    country_policy = BLOCK_POLICY
else:
    default_policy = BLOCK_POLICY
    block_policy = BLOCK_POLICY
    country_policy = 'accept'

# Setting urllib
ctx = ssl.create_default_context()
IGNORE_CERTIFICATE = False
if IGNORE_CERTIFICATE:
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

https_handler = urllib.request.HTTPSHandler(context=ctx)

opener = urllib.request.build_opener(https_handler)
# opener.addheaders = [('User-agent', 'Mozilla/5.0 (X11; Linux x86_64)')]
opener.addheaders = [('User-agent', 'Mozilla/5.0 (compatible; nft-blackhole/0.1.0; '
                      '+https://github.com/tomasz-c/nft-blackhole)')]
urllib.request.install_opener(opener)

def stop():
    '''Stopping nft-blackhole'''
    run(['/usr/bin/nft', 'delete', 'table', 'inet', 'blackhole'], check=False)

def start():
    '''Starting nft-blackhole'''
    nft_template = open('/usr/share/nft-blackhole/nft-blackhole.template').read()
    nft_conf = Template(nft_template).substitute(default_policy=default_policy,
                                                 block_policy=block_policy,
                                                 country_policy=country_policy)
    run(['/usr/bin/nft', '-f', '-'], input=nft_conf.encode(), check=True)


def get_urls(urls, do_filter=False):
    '''Download url in threads'''
    ip_list_aggregated = []
    def get_url(url):
        try:
            response = urllib.request.urlopen(url, timeout=10)
            content = response.read().decode('utf-8')
        except BaseException as exc:
            print('ERROR', getattr(exc, 'message', repr(exc)), url, file=stderr)
            ip_list = []
        else:
            if do_filter:
                content = re.sub(r'^ *(#.*\n?|\n?)', '', content, flags=re.MULTILINE)
            ip_list = content.splitlines()
        return ip_list
    with ThreadPoolExecutor(max_workers=8) as executor:
        do_urls = [executor.submit(get_url, url) for url in urls]
        for out in as_completed(do_urls):
            ip_list = out.result()
            ip_list_aggregated += ip_list
    return ip_list_aggregated


def get_blacklist(ip_ver):
    '''Get blacklists'''
    urls = []
    for bl_url in BLACKLIST[ip_ver]:
        urls.append(bl_url)
    ips = get_urls(urls, do_filter=True)
    return ips


def get_country_ip_list(ip_ver):
    '''Get country lists from GitHub @herrbischoff'''
    urls = []
    for country in COUNTRY_LIST:
        url = f'https://raw.githubusercontent.com/herrbischoff/country-ip-blocks/master/ip{ip_ver}/{country.lower()}.cidr'
        urls.append(url)
    ips = get_urls(urls)
    return ips


def get_country_ip_list2(ip_ver):
    '''Get country lists from ipdeny.com'''
    urls = []
    for country in COUNTRY_LIST:
        if ip_ver == 'v4':
            url = f'http://ipdeny.com/ipblocks/data/aggregated/{country.lower()}-aggregated.zone'
        elif ip_ver == 'v6':
            url = f'http://ipdeny.com/ipv6/ipaddresses/aggregated/{country.lower()}-aggregated.zone'
        urls.append(url)
    ips = get_urls(urls)
    return ips


def whitelist_sets(reload=False):
    '''Create whitelist sets'''
    for ip_ver in IP_VER:
        set_name = f'whitelist-{ip_ver}'
        set_list = ','.join(WHITELIST[ip_ver])
        nft_set = (Template(SET_TEMPLATE).substitute(ip_ver=f'ip{ip_ver}', set_name=set_name, ip_list=set_list))
        if reload:
            run(['/usr/bin/nft', 'flush', 'set', 'inet', 'blackhole', set_name], check=False)
        if WHITELIST[ip_ver]:
            run(['/usr/bin/nft', '-f', '-'], input=nft_set.encode(), check=True)

def blacklist_sets(reload=False):
    '''Create blacklist sets'''
    for ip_ver in IP_VER:
        set_name = f'blacklist-{ip_ver}'
        ip_list = get_blacklist(ip_ver)
        set_list = ','.join(ip_list)
        nft_set = (Template(SET_TEMPLATE).substitute(ip_ver=f'ip{ip_ver}', set_name=set_name, ip_list=set_list))
        if reload:
            run(['/usr/bin/nft', 'flush', 'set', 'inet', 'blackhole', set_name], check=False)
        if ip_list:
            run(['/usr/bin/nft', '-f', '-'], input=nft_set.encode(), check=True)

def country_sets(reload=False):
    '''Create country sets'''
    for ip_ver in IP_VER:
        set_name = f'country-{ip_ver}'
        ip_list = get_country_ip_list(ip_ver)
        set_list = ','.join(ip_list)
        nft_set = (Template(SET_TEMPLATE).substitute(ip_ver=f'ip{ip_ver}', set_name=set_name, ip_list=set_list))
        if reload:
            run(['/usr/bin/nft', 'flush', 'set', 'inet', 'blackhole', set_name], check=False)
        if ip_list:
            run(['/usr/bin/nft', '-f', '-'], input=nft_set.encode(), check=True)


# Main
if action == 'start':
    start()
    whitelist_sets()
    blacklist_sets()
    country_sets()
elif action == 'stop':
    stop()
elif action == 'restart':
    stop()
    start()
    whitelist_sets()
    blacklist_sets()
    country_sets()
elif action == 'reload':
    whitelist_sets(reload=True)
    blacklist_sets(reload=True)
    country_sets(reload=True)

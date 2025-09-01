# nft-blackhole
Daemon blocking IP addresses upon country or blacklist, using nftables

## Table of contents

- [Overview](#overview)
- [Installation](#installation)
  - [Arch Linux](#arch-linux)
  - [Debian Linux](#debian-linux)
  - [Manual](#manual)
- [Configuration](#configuration)
    - [Set the configuration in a file](#set-the-configuration-in-a-file)
- [Usage](#usage)
  - [Manual](#manual)
  - [With systemd](#with-systemd)
  - [List counter packages dropped/accept](#list-counter-packages-droppedaccept)
  - [List table and sets for blackhole](#list-table-and-sets-for-blackhole)
  - [Refresh lists](#refresh-lists)
- [Credits](#credits)
- [License](#license)

## Overview

##### Features
- download publicly available blacklists and block IPs from them,
- block or whitelist countries,
- whitelist network or IP address,

##### Configuration file
###### In the configuration file you can define:
- IP versions supported (IPv4, IPv6),
- blocking policy (reject, drop,)
- white list (network or IP addresses),
- blacklist URL,
- block output connections to blacklisted IPs,
- list of countries,
- policy for countries (accept, block),
- ports excluded from country blocks

## Installation
### Arch Linux
##### Install from AUR package `nft-blackhole`
For example:

    yay -S nft-blackhole
    pikaur -S nft-blackhole

### Debian Linux
Tested with Debian buster 10

##### Download the debian-10 branch of this repository

    git clone -b debian-10 https://github.com/tomasz-c/nft-blackhole.git

##### Install requirements

    sudo apt install nftables python3-yaml

##### Install files
    sudo cp -i nft-blackhole.conf /etc/
    sudo cp -i nft-blackhole.py   /usr/local/sbin/
    sudo mkdir /usr/share/nft-blackhole
    sudo cp -i nft-blackhole.template /usr/share/nft-blackhole/
    sudo cp -i nft-blackhole.service        /lib/systemd/system/
    sudo cp -i nft-blackhole-reload.service /lib/systemd/system/
    sudo cp -i nft-blackhole-reload.timer   /lib/systemd/system/
    [[ -f /usr/bin/nft-blackhole.py ]] && echo "BEWARE, another version is already installed"

### Manual
##### Requirements
- nftables
- python 3.6+
- python-yaml
- systemd (for daemon)

##### File location
    /usr/local/sbin/nft-blackhole.py
    /usr/share/nft-blackhole/nft-blackhole.template
    /etc/nft-blackhole.conf
    /usr/lib/systemd/system/nft-blackhole.service
    /usr/lib/systemd/system/nft-blackhole-reload.service
    /usr/lib/systemd/system/nft-blackhole-reload.timer

## Configuration
#### Set the configuration in a file
`/etc/nft-blackhole.conf`

## Usage
### Manual
##### As root:
	/usr/local/sbin/nft-blackhole.py start
	/usr/local/sbin/nft-blackhole.py reload
	/usr/local/sbin/nft-blackhole.py restart
	/usr/local/sbin/nft-blackhole.py stop

### With systemd
##### As root:
    systemctl enable nft-blackhole.service
	systemctl start nft-blackhole.service
	systemctl reload nft-blackhole.service
	systemctl restart nft-blackhole.service

### List packets counters
    nft list chain inet blackhole input
### List table and sets for blackhole
    nft list table inet blackhole
### Refresh lists

nft-blackhole can download new versions of any blacklist it uses.  You can trigger this manually, however it is better to have it automatically and periodically done (either thanks to a cron job or to a Systemd timer).

#### Manual

    /usr/local/sbin/nft-blackhole.py reload
    systemctl reload nft-blackhole.service

#### Crontab
    
    0 */6 * * * systemctl reload nft-blackhole.service

#### Systemd Timer

    systemctl enable --now nft-blackhole-reload.timer
    systemctl list-timers --all

## Credits
[country-ip-blocks](https://github.com/herrbischoff/country-ip-blocks) - CIDR country-level IP lists,

[https://iplists.firehol.org/](https://iplists.firehol.org/) - aggregated, publicly available blacklists

## License

Code released under [MIT](./LICENSE) license.

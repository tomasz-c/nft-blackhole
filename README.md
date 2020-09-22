

# nft-blackhole
Script / daemon to blocking IP in nftables by country and black lists.

## Table of contents

- [Overview](#overview)
- [Installation](#installation)
  - [Arch Linux Users](#arch-linux-users)
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
- block or whitelist individual countries,
- whitelist individual networks or IP addresses,

##### Configuration file
###### In the configuration file you can define:
- IP versions supported (ipv4, ipv6),
- blocking policy (reject, drop,)
- network or IP addresses for the white list,
- blacklist url addresses,
- list of countries,
- policy for countries (accept, block)

## Installation
### Arch Linux Users
##### Install from AUR package `nft-blackhole`
For example:

    yay -S nft-blackhole
    pikaur -S nft-blackhole

### Manual
##### Requirements
- nftables
- python 3.6+
- python-yaml
- systemd (for daemon)

##### File location
    /usr/bin/nft-blackhole.py
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
	/usr/bin/nft-blackhole.py start
	/usr/bin/nft-blackhole.py reload
	/usr/bin/nft-blackhole.py restart
	/usr/bin/nft-blackhole.py stop

### With systemd
##### As root:
    systemctl enable nft-blackhole.service
	systemctl start nft-blackhole.service
	systemctl reload nft-blackhole.service
	systemctl restart nft-blackhole.service

### List counter packages dropped/accept
    nft list chain inet blackhole input
### List table and sets for blackhole
    nft list table inet blackhole
### Refresh lists
#### Manual

    /usr/bin/nft-blackhole.py reload
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

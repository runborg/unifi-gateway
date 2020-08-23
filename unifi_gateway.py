# -*- coding: utf-8 -*-
import configparser
import argparse
import logging.handlers
import socket
import time

import urllib
import urllib.error

from daemon import Daemon
from unifi_protocol import create_broadcast_message, send_inform
import json
from packtest import packet
import aquire
from random import randint
import hashlib
import psutil

DEFAULT_AUTHKEY = hashlib.md5(b'ubnt').digest().hex()  # 'ba86f2bbe107c7c57eb5f2690775c712'

handler = logging.handlers.SysLogHandler(address='/dev/log')
handler.setFormatter(logging.Formatter('[unifi-gateway] : %(levelname)s : %(message)s'))
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.addHandler(handler)

ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
logger.addHandler(ch)

proto_logger = logging.getLogger('unifi_protocol')
proto_logger.setLevel(logging.DEBUG)
proto_logger.addHandler(ch)

CONFIG_FILE = 'conf/unifi-gateway.conf'


def print_bytearray(value, size=32):
    _data = [f'{b:02x}' for b in value]
    for i,d in enumerate(_data):
        print(f'{d} ', end='')

        if (i+1) % size == 0:
            print()
    print()


def mgmt_decode(items):
    return dict(map(lambda s : s.split('='), items))


class UnifiGateway(Daemon):

    def __init__(self, **kwargs):
        self.interval = 10
        self.config = configparser.RawConfigParser()
        self.config.read(CONFIG_FILE)
        self.authkey = self.config.get('gateway', 'key', fallback=DEFAULT_AUTHKEY)
        self.url = self.config.get('gateway', 'url', fallback='http://unifi:8080/inform')
        self.cfgversion = '?'
        self.is_adopted = False if self.authkey == DEFAULT_AUTHKEY else True
        self.encryption = self.config.get('gateway', 'encryption', fallback='CBC')

        Daemon.__init__(self, pidfile=self.config.get('global', 'pid_file'), **kwargs)

    def run(self):
        self.url = self.config.get('gateway', 'url')
        while True:
            logger.debug(f'run: Sending request to {self.url}')
            response = None
            try:
                _response = send_inform(self.create_inform(),
                                        url=self.config.get('gateway', 'url'),
                                        key=self.authkey,
                                        encryption=self.encryption)
            except urllib.error.HTTPError as E:
                logger.error("HTTP Error")
                logger.error(E)
                time.sleep(self.interval)
                continue

            if _response:
                response = json.loads(str(_response))
                logger.debug(f'run: response from server: {response}')

                if response['_type'] == 'setparam':

                    if 'mgmt_cfg' in response:
                        mgmt_cfg = mgmt_decode(response['mgmt_cfg'].splitlines())
                        if 'authkey' in mgmt_cfg:
                            self.authkey = mgmt_cfg['authkey']
                            self.config.set('gateway', 'is_adopted', True)

                        if 'cfgversion' in mgmt_cfg:
                            self.cfgversion = mgmt_cfg['cfgversion']

                        if 'use_aes_gcm' in mgmt_cfg and mgmt_cfg['use_aes_gcm']:
                            logger.debug('Setting encryption to GCM')
                            self.encryption = 'GCM'
                            self.config.set('gateway', 'encryption', 'GCM')

                    for key, value in list(response.items()):
                        if key == 'mgmt_cfg':
                            self.authkey == value

                    self._save_config()

            time.sleep(self.interval)

    def quit(self):
        pass

    def set_adopt(self, url, key):
        self.config.set('gateway', 'url', url)
        self.config.set('gateway', 'key', key)
        self._save_config()

        response = self._send_inform(create_inform(), url=self.config.get('gateway', 'url'))
        logger.debug('Receive {} from controller'.format(response))
        if response['_type'] == 'setparam':
            for key, value in list(response.items()):
                if key not in ['_type', 'server_time_in_utc', 'mgmt_cfg']:
                    self.config.set('gateway', key, value)
            self.config.set('gateway', 'is_adopted', True)
            self._save_config()

    def _save_config(self):
        with open(CONFIG_FILE, 'w') as config_file:
            self.config.set('gateway', 'key', self.authkey)

            self.config.write(config_file)

    def _create_nic_stats(self, nic):
        netstats = aquire.network_statistics()
        return {
            'enable': True,
            'full_duplex': True,
            'gateways': [
            ],
            'ip': '158.38.145.81',
            'latency': 4,
            'mac': '80:2a:a8:cd:a9:54',
            'name': 'eth0',
            'nameservers': [
            ],
            'netmask': '255.255.255.192',
            'num_port': 1,
            'drops': netstats[nic].rx_dropped,
            'rx_bytes': netstats[nic].rx_bytes,
            'rx_dropped': netstats[nic].rx_dropped,
            'rx_errors': netstats[nic].rx_errors,
            'rx_multicast': netstats[nic].rx_multicast,
            'rx_packets': netstats[nic].rx_packets,
            'speed': 1000,
            # 'speedtest_lastrun': int(time.time()),
            # 'speedtest_ping': randint(0, 2000),
            # 'speedtest_status': 'Idle',
            'tx_bytes': netstats[nic].tx_bytes,
            'tx_dropped': netstats[nic].tx_dropped,
            'tx_errors': netstats[nic].tx_errors,
            'tx_packets': netstats[nic].tx_packets,
            'up': True,
            'uptime': aquire.uptime(),
            'xput_down': 0,
            'xput_up': 0,
        }

    def _create_empty_nic_stats(self, nic):
        {
            'enable': False,
            'name': nic,
            'up': False,
        }

    def _create_complete_inform(self):
        lan1_nic = 'eth0'
        if lan1_nic:
            lan1_stats = self._create_nic_stats(lan1_nic)
        else:
            lan1_stats = self._create_empty_stats(lan1_nic)

        pkg = {
            'mac': 'f0:9f:c2:79:34:fd',
            'ip': '158.38.145.81',
            'netmask': '255.255.255.0',
            'model': 'UGW4',
            'model-display': 'UniFi-Gateway-4',
            'version': '4.4.51.5287926',

            'hostname': 'UBNT',
            'inform_url': 'http://158.38.145.72:8080/inform',
            'last_error': "Unknown[11] (http://158.38.145.72:8080/inform)",
            'isolated': False,
            "default": not self.is_adopted,
            'uptime': aquire.uptime(),
            'cfgversion': self.cfgversion,
            'led_enabled': True,
            'discovery_response': not self.is_adopted,
            'has_dpi': False,
            'serial': self.config.get('gateway', 'lan_mac').replace(':', ''),

            'bootrom_version': 'unknown',
            'required_version': '4.0.0',

            'system-stats': {
                'cpu': '%s' % psutil.cpu_percent(),
                'mem': '%s' % (100 - psutil.virtual_memory()[2]),
                'uptime':  '%s' % aquire.uptime()
            },


            'config_network_wan': {'type': 'dhcp'},
            'config_port_table': [
                {'ifname': 'eth0', 'name': 'lan'},
                {'ifname': 'eth1', 'name': 'lan'},
                {'ifname': 'eth2', 'name': 'lan'},
                {'ifname': 'eth3', 'name': 'wan'}
                ],
            'has_eth1': True,
            'has_porta': True,
            'has_ssh_disable': True,
            'time': int(time.time()),
            'uplink': 'eth3',
            #'routes': [
            #    {   
            #        'nh': [{'intf': 'eth0', 'metric': '1/0', 't': 'S>*', 'via': '20.1.1.1'}],
            #        'pfx': '0.0.0.0/0'
            #        }],
            'if_table': [
                lan1_stats,
                {
                    'enable': False,
                    'full_duplex': True,
                    'speed': 100,
                    'name': 'eth1',
                    'up': True,
                },
                {
                    'enable': False,
                    'full_duplex': True,
                    'up': False
                },
                {
                    'enable': True,
                    'full_duplex': True,
                    'ip': '1.1.1.1/24',
                    'mac': '80:2a:a8:cd:a9:53',
                    'name': 'eth3',
                    'netmask': '255.255.255.0',
                    'num_port': 1,
                    'rx_bytes': 807912794876,
                    'rx_dropped': 2800,
                    'rx_errors': 0,
                    'rx_multicast': 412314,
                    'rx_packets': 700376545,
                    'speed': 1000,
                    'tx_bytes': 58901673253,
                    'tx_dropped': 0,
                    'tx_errors': 0,
                    'tx_packets': 347161831,
                    'up': True
                },
                
            ],
            #'network_table': [
            #    {
            #        'address': '192.168.1.1/24',
            #        'addresses': [
            #            '%s/24' % '1.1.1.1'
            #        ],
            #        'autoneg': 'true',
            #        'duplex': 'full',
            #        'host_table': [
            #        ],
            #        'l1up': 'true',
            #        'mac': '80:2a:a8:cd:a9:53',
            #        'mtu': '1500',
            #        'name': 'eth1',
            #        'speed': '1000',
            #        'stats': {
            #            'multicast': '412294',
            #            'rx_bps': '342',
            #            'rx_bytes': 52947224765,
            #            'rx_dropped': 2800,
            #            'rx_errors': 0,
            #            'rx_multicast': 412314,
            #            'rx_packets': 341232922,
            #            'tx_bps': '250',
            #            'tx_bytes': 792205417381,
            #            'tx_dropped': 0,
            #            'tx_errors': 0,
            #            'tx_packets': 590930778
            #        },
            #        'up': 'true'
            #    }
            #    ],
            }
        return pkg

    def create_inform(self):
        return self._create_complete_inform()


def restart(args):
    UnifiGateway().restart()


def stop(args):
    UnifiGateway().stop()


def start(args):
    UnifiGateway().start()


def set_adopt(args):
    url, key = args.s, args.k
    UnifiGateway().set_adopt(url, key)


def run(args):
    UnifiGateway().run()


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers()

    parser_start = subparsers.add_parser('start', help='start unifi gateway daemon')
    parser_start.set_defaults(func=start)

    parser_run = subparsers.add_parser('run', help='Start unify gateway in the foreground')
    parser_run.set_defaults(func=run)

    parser_stop = subparsers.add_parser('stop', help='stop unifi gateway daemon')
    parser_stop.set_defaults(func=stop)

    parser_restart = subparsers.add_parser('restart', help='restart unifi gateway daemon')
    parser_restart.set_defaults(func=restart)

    parser_adopt = subparsers.add_parser('set-adopt', help='send the adoption request to the controller')
    parser_adopt.add_argument('-s', type=str, help='controller url', required=True)
    parser_adopt.add_argument('-k', type=str, help='key', required=True)
    parser_adopt.set_defaults(func=set_adopt)

    args = parser.parse_args()
    args.func(args)

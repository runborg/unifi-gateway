from collections import namedtuple
from pprint import pprint
import os

InterfaceData = namedtuple('InterfaceData', ['rx_bytes', 'rx_packets', 'rx_errors', 'rx_dropped',
                                             'rx_fifo', 'rx_frames', 'rx_compressed', 'rx_multicast',
                                             'tx_bytes', 'tx_packets', 'tx_errors', 'tx_dropped',
                                             'tx_fifo', 'collitions', 'carrier', 'tx_compressed'])


def network_statistics():
    with open('/proc/net/dev') as _f:
        data = {}

        dump = _f.readlines()

        for _line in dump[2:]:
            line = _line.split(':')
            tempdata = []
            for _d in line[1].split():
                tempdata.append(int(_d))
            data[line[0].strip()] = InterfaceData(*tempdata)

        return data


def get_macaddress(interface):
    if not os.path.isdir(f'/sys/class/net/{interface}'):
        raise KeyError('The specified interface {interface} is not found')
    with open(f'/sys/class/net/{interface}/address') as _f:
        mac = _f.read().strip()

    return mac


def list_interfaces():
    return os.listdir('/sys/class/net/')


def uptime():
    with open('/proc/uptime', 'r') as f:
        _ut, _ = f.readline().split(' ')
        uptime_fl = float(_ut)
        return int(uptime_fl)


if __name__ == '__main__':
    print('Network statistics')
    netstat = network_statistics()
    pprint(netstat)
    print()
    print('Listing interfaces')
    print(list_interfaces())

    print('Interface Mac addresses:')
    for i in list_interfaces():
        mac = get_macaddress(i)
        print(f'{i:10} {mac}')

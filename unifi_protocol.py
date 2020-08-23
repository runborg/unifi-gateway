# -*- coding: utf-8 -*-
import json
import logging

import zlib

from Cryptodome import Random
from Cryptodome.Cipher import AES

from struct import pack, unpack

from binascii import a2b_hex, hexlify

from tlv import UnifiTLV
from tools import mac_string_2_array, ip_string_2_array

from urllib.parse import urlparse
import http.client
import aquire

logger = logging.getLogger(__name__)


class InformPacket():
    def __init__(self, version, mac, flags, iv, payload_ver, payload_len, payload):
        self.version = version
        self.mac = mac
        self.flags = flags
        self.iv = iv
        self.payload_ver = payload_ver
        self.payload_len = payload_len
        self.payload = payload

    def __str__(self):
        return self.payload.decode()

    def __repr__(self):
        return 'InformPacket()'


def send_inform(data, url='http://unifi:8080/inform', key='00000000000000000000000000000000', encryption='CBC'):
    if not isinstance(data, dict):
        raise TypeError('Data needs to be a dictionary object')
    if not data['mac']:
        raise Exception('data needs to include a mac field')

    str_request = json.dumps(data)
    request = str_request.encode('utf-8')

    logger.debug(f'send_inform: using url to {url}')
    url = urlparse(url)
    _inform = encode_inform(key, request, data['mac'], encryption=encryption)

    logger.debug(f'send_inform: Send inform request to {url.geturl()}')
    logger.debug(f'send_inform: Payload: {data}')

    conn = http.client.HTTPConnection(url.hostname, url.port)
    conn.putrequest("POST", url.path, skip_accept_encoding=True)
    conn.putheader('Accept', '*/*')
    conn.putheader('User-Agent', 'AirControl Agent v1.0')
    conn.putheader('Content-Type', 'application/x-binary')
    conn.putheader('Content-Length', len(_inform))
    conn.putheader('Expect', '100-continue')

    conn.endheaders()

    # print_bytearray(_inform)
    conn.send(_inform)
    # conn.request("POST", "/inform", _inform, headers)
    response = conn.getresponse()

    if response.status == 404:
        # The response seems valid, but we are not added to the controller
        # retrying and waiting until we get a valid response
        logger.debug(f'send_inform: Response: 404 from controller, are we adopted?')
        return None
    elif response.status == 200:
        logger.debug(f'send_inform: Response: {response.status}')
        response_payload = response.read()
        return decode_inform(key, response_payload)

    raise Exception(f'We got an invalid response from the server http{response.status}')


def encode_inform(key, data, mac=b'f0:9f:c2:79:34:fb', encryption='CBC', zlibCompressed=True):
    # TODO: For now compression and AES is hardcoded..
    iv = Random.new().read(16)
    binary_key = a2b_hex(key)
    tuple_mac = tuple([int(i, 16) for i in mac.split(':')])

    payload = data
    flags = 0x00

    if encryption == 'GCM':
        flags = flags | 0x01 | 0x08
    elif encryption == 'CBC':
        flags = flags | 0x01

    # zlib compression
    if zlibCompressed:
        logger.debug('encode_inform: Zlib compressing package')
        payload = zlib.compress(payload)
        flags = flags | 0x02

    # encode packet
    output = b'TNBU'                    # magic
    output += pack('>I', 1)             # packet version
    output += pack('BBBBBB', *tuple_mac)   # mac address
    output += pack('>H', flags)          # flags
    output += iv                        # encryption iv
    output += pack('>I', 1)             # payload version

    # Header needs to be completed before the package is encrypted because GCM uses the header as AAD
    # payload length is added after the correct encryption method is selected because of this

    if encryption == 'GCM':
        # GCM Encryption
        logger.debug(f'encode_indorm: AES GCM Encrypting packet using key {key} and iv {hexlify(iv)}')
        output += pack('>I', len(payload)+16)  # payload length
        _aes = AES.new(binary_key, AES.MODE_GCM, iv)
        _aes.update(output)
        payload, tag = _aes.encrypt_and_digest(payload)
        payload += tag

    elif encryption == 'CBC':
        logger.debug(f'encode_inform: AES CBC Encrypting packet using key: {key} and iv {hexlify(iv)}')
        
        # padding - http://stackoverflow.com/a/14205319
        pad_len = AES.block_size - (len(payload) % AES.block_size)
        payload += bytearray([pad_len for i in range(pad_len)])
        output += pack('>I', len(payload))  # payload length
        # encryption
        payload = AES.new(binary_key, AES.MODE_CBC, iv).encrypt(payload)

    elif encryption:
        # encrypted is still set but not fetched by any allowed algoritms
        raise NotImplementedError(f'The encryption algoritm {encryption} is not supported')

    else:
        output += pack('>I', len(payload))


    logger.debug(f'encode_inform: header: magic: {hexlify(output[0:4])}, version: {hexlify(output[4:8])}, mac: {hexlify(output[8:14])}, \n'
                 f'encode_inform: header: flags: {hexlify(output[14:16])}, iv: {hexlify(output[16:32])}, payload_ver: {hexlify(output[32:36])}, payload_len: {hexlify(output[36:40])}')
    output += payload

    return output


def decode_inform(key, data):
    magic = data[0:4]
    if magic != b'TNBU':
        raise Exception("Missing magic in response: '%s' instead of 'TNBU'" %(magic))
    binary_key = a2b_hex(key)
    header = data[:40]
    version = bytes(unpack('>I', data[4:8]))
    mac = bytes(unpack('BBBBBB', data[8:14]))
    flags = unpack('>H', data[14:16])[0]
    iv = data[16:32]
    payload_ver = unpack('>I', data[32:36])[0]
    payload_len = unpack('>I', data[36:40])[0]
    payload = data[40:(40+payload_len)]

    flag = {
        'encrypted': bool(flags & 0x01),
        'zlibCompressed': bool(flags & 0x02),
        'SnappyCompression': bool(flags & 0x04),
        'encryptedGCM': bool(flags & 0x08),
    }

    if flag['encrypted']:
        if flag['encryptedGCM']:
            tag = payload[-16:]
            payload = payload[:-16]
            _aes = AES.new(binary_key, AES.MODE_GCM, iv)
            _aes.update(header)
            payload = _aes.decrypt_and_verify(payload, tag)
        else:
            # Encrypted with AES encryption
            _aes = AES.new(binary_key, AES.MODE_CBC, iv)
            payload = _aes.decrypt(payload)
            # unpad - https://gist.github.com/marcoslin/8026990#file-server-py-L43
            pad_size = payload[-1]
            if pad_size > AES.block_size:
                raise Exception('Response not padded or padding is corrupt, possibly not decrypted correctly')
            payload = payload[:(len(payload) - pad_size)]      

    # uncompress if required
    if flag['zlibCompressed']:
        try:
            payload = zlib.decompress(payload)
        except zlib.error:
            raise Exception('Unable to uncompress data, possibly not decrypted correctly')

    return InformPacket(version, mac, flag, iv, payload_ver, payload_len, payload)


def create_broadcast_message(config, index, version=2, command=6):
    lan_mac = config.get('gateway', 'lan_mac')
    lan_ip = config.get('gateway', 'lan_ip')
    firmware = config.get('gateway', 'firmware')
    device = config.get('gateway', 'device')

    tlv = UnifiTLV()
    tlv.add(1, bytearray(mac_string_2_array(lan_mac)))
    tlv.add(2, bytearray(mac_string_2_array(lan_mac) + ip_string_2_array(lan_ip)))
    tlv.add(3, bytearray(f'{device}.v{firmware}'.encode()))
    tlv.add(10, bytearray(pack('!I', aquire.uptime())))
    tlv.add(11, bytearray(b'UGW3'))
    tlv.add(12, bytearray(device.encode()))
    tlv.add(19, bytearray(mac_string_2_array(lan_mac)))
    tlv.add(18, bytearray(pack('!I', index)))
    tlv.add(21, bytearray(device.encode()))
    tlv.add(27, bytearray(firmware.encode()))
    tlv.add(22, bytearray(firmware.encode()))
    return tlv.get(version=version, command=command)

import base64
import json
import difflib
# import struct

# import zlib

from binascii import a2b_hex
from flask import Flask, request
# from struct import pack, unpack
# import binascii

from inform import packet_decode


class encryptionError(Exception):
    pass


app = Flask(__name__)

key = 'ba86f2bbe107c7c57eb5f2690775c712'

last_message = []


@app.route("/inform", methods=['POST'])
def inform():
    global last_message
    data = request.get_data()

    binary_key = a2b_hex(key)
    _data = packet_decode(binary_key, data)
    decoded = json.loads(_data.payload)

    if not _data.flags['encryptedGCM']:
        print('NOT GCM')
        return ''

    print('GCM PACKET')

    new_message = json.dumps(decoded, indent=4).split('\n')

    # diff = difflib.unified_diff(last_message, new_message)

    # print('\n'.join(list(diff)))

    last_message = new_message
    # print('headers:')
    # print(request.headers)
    # print('Data:')
    # print_bytearray(data)
    # print()
    print(_data)
    return ''

# mca-ctrl -t connect -s "http://10.0.8.2:8080/inform" -k "A09E428C482EB53C7731C224295CD9D3"


def print_bytearray(value, size=32):
    _data = [f'{b:02x}' for b in value]
    for i, d in enumerate(_data):
        print(f'{d} ', end='')

        if (i+1) % size == 0:
            print()
    print()


app.run(debug=True, port=8080, host='0.0.0.0')

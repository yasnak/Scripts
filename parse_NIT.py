"""
NIT actual parsing script.
This is to check packet values with binary data.
"""

import sys
from struct import *

BUFFER_SIZE = 16 * 1024     # This is to avoid crashing by loading huge binary file.
LINE_SIZE = 16  # Data size to display in 1 line.


def bin2dump(data):
    """Display dumped text."""
    offset = 0
    while True:
        linedata = data[offset: offset + LINE_SIZE]
        print(linedata)
        offset += LINE_SIZE
        if offset >= len(data):
            break


def parse_NIT_actual(data):
    """Parse and display NIT actual. (based on HA_SI spec rev.1.3 p.111)"""
    print('network_information_section()')
    offset = 0

    structure_fmt = '>BHHBBBH'
    unpacked = unpack_from(structure_fmt, data, offset)
    print('table_id: {:#x}'.format(unpacked[0]))
    print('section_syntax_indicator:', bin(unpacked[1] >> 15))
    print('reserved_future_use:', bin(unpacked[1] & 0b0111111111111111 >> 14))
    print('reserved:', bin(unpacked[1] & 0b0011111111111111 >> 12))
    section_length = unpacked[1] & 0x0fff
    print('section_length:', section_length)
    # Data size verification
    if len(data) - 3 != section_length:
        print('''Error: The length inside is not match to the binary data size.
        Data size:{}, Expected size:{}'''.format(len(data), section_length + 3))
        return 1
    print('network_id:', unpacked[2])
    print('reserved:', bin(unpacked[3] >> 6))
    print('version_number:', bin(unpacked[3] & 0b00111111 >> 1))
    print('current_next_indicator:', bin(unpacked[3] & 0b00000001))
    print('section_number:', unpacked[4])
    print('last_section_number:', unpacked[5])
    network_descriptor_length = unpacked[6] & 0x0fff
    print('reserved_future_use:', bin(unpacked[6] >> 12))
    print('network_descriptor_length:', network_descriptor_length)
    offset += calcsize(structure_fmt)

    # 1st loop for network_name_descriptor.
    structure_fmt = '>BB'
    unpacked = unpack_from(structure_fmt, data, offset)
    print(' descriptor_tag: {:#x}'.format(unpacked[0]))
    print(' descriptor_length:', unpacked[1])
    loop_offset = offset + calcsize(structure_fmt)
    print(' char:', data[loop_offset:loop_offset + unpacked[1]])
    # print('debug:', data[loop_offset:loop_offset + 20]) #WORNING: length is match.
    offset += network_descriptor_length

    structure_fmt = '>H'
    unpacked = unpack_from(structure_fmt, data, offset)
    print('reserved_future_use:', bin(unpacked[0] >> 12))
    transport_stream_loop_length = unpacked[0] & 0x0fff
    print('transport_stream_loop_length:', transport_stream_loop_length)
    offset += calcsize(structure_fmt)

    while transport_stream_loop_length > 0:
        structure_fmt = '>HHH'
        unpacked = unpack_from(structure_fmt, data, offset)
        print(' transport_stream_id: {:#x}'.format(unpacked[0]))
        print(' original_network_id: {:#x}'.format(unpacked[1]))
        print(' reserved_future_use:', bin(unpacked[2] >> 12))
        transport_descriptors_length = unpacked[2] & 0x0fff
        print(' transport_descriptors_length:', transport_descriptors_length)
        offset += calcsize(structure_fmt)
        transport_stream_loop_length -= calcsize(structure_fmt)

        # 2nd loop for service_list_descriptor.
        structure_fmt = '>BB'
        unpacked = unpack_from(structure_fmt, data, offset)
        print('  descriptor_tag: {:#x}'.format(unpacked[0]))
        descriptor_length = unpacked[1]
        print('  descriptor_length:', descriptor_length)
        loop_offset = offset + calcsize(structure_fmt)
        structure_fmt = '>HB'
        while descriptor_length > 0:
            unpacked = unpack_from(structure_fmt, data, loop_offset)
            print('  service_id: {:#x}'.format(unpacked[0]))
            print('  service_type: {:#x}'.format(unpacked[1]))
            loop_offset += calcsize(structure_fmt)
            descriptor_length -= calcsize(structure_fmt)
        offset += transport_descriptors_length
        transport_stream_loop_length -= transport_descriptors_length

    structure_fmt = '>L'
    unpacked = unpack_from(structure_fmt, data, offset)
    print('CRC_32: {:#x}'.format(unpacked[0]))
  

# Main routine.
with open(sys.argv[1], 'rb') as ifile:
    data = ifile.read(BUFFER_SIZE)
    if len(data) == BUFFER_SIZE:
        print("Error: Data size is beyond the buffer size.")
        sys.exit(1)
  
parse_NIT_actual(data)

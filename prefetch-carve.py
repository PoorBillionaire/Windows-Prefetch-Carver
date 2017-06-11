#!/usr/bin/python

from __future__ import print_function

import sys
import mmap
import struct
import contextlib
from argparse import ArgumentParser
from datetime import datetime,timedelta


prefetch_types = [17, 23, 26]

header_members = [
    u'version',
    u'signature',
    u'unknown_0',
    u'file_size',
    u'exe_name',
    u'prefetch_hash',
    u'unknown_1'
]

file_info_members_v17 = [
    u'metrics_offset',
    u'metrics_count',
    u'trace_chains_offset',
    u'trace_chains_count',
    u'filename_strings_offset',
    u'filename_strings_size',
    u'volumes_info_offset',
    u'volumes_count',
    u'volumes_info_size',
    u'last_run_time',
    u'unknown_0',
    u'run_count',
    u'unknown_1'
]

file_info_members_v23 = [
    u'metrics_offset',
    u'metrics_count',
    u'trace_chains_offset',
    u'trace_chains_count',
    u'filename_strings_offset',
    u'filename_strings_size',
    u'volumes_info_offset',
    u'volumes_count',
    u'volumes_info_size',
    u'unknown_0',
    u'last_run_time',
    u'unknown_1',
    u'run_count',
    u'unknown_2'
]

file_info_members_v26 = [
    u'metrics_offset',
    u'metrics_count',
    u'trace_chains_offset',
    u'trace_chains_count',
    u'filename_strings_offset',
    u'filename_strings_size',
    u'volumes_info_offset',
    u'volumes_count',
    u'volumes_info_size',
    u'unknown_0',
    u'last_run_time',
    u'execution_time_1',
    u'execution_time_2',
    u'execution_time_3',
    u'execution_time_4',
    u'execution_time_5',
    u'execution_time_6',
    u'execution_time_7',
    u'unknown_1',
    u'run_count',
    u'unknown_2'
]

def parse_file_information(version, mfile, offset):
    if version == 17:
        file_info = struct.unpack("<9IQ16s2I", mfile[offset:offset + 68])
        file_info_dict = dict(zip(file_info_members_v17, file_info))
        offset += 68
    elif version == 23:
        file_info = struct.unpack("<9I2Q16sI84s", mfile[offset:offset + 156])
        file_info_dict = dict(zip(file_info_members_v23, file_info))
        offset += 156
    else:
        file_info = struct.unpack("<9I8s8Q16sI96s", mfile[offset:offset + 224])
        file_info_dict = dict(zip(file_info_members_v26, file_info))
        offset += 224
    return process_fileinfo_members(file_info_dict), offset

def filenameHandler(exe_name):
    end = exe_name.find(b'\x00\x00')
    exe_name = exe_name[0:end + 1].decode("utf16")
    return exe_name

def process_fileinfo_members(fileinfo_dict):
    fileinfo_dict['last_run_time_human'] = \
        filetime_to_human(fileinfo_dict[u'last_run_time'])

    fileinfo_dict['last_run_time_epoch'] = \
        filetime_to_epoch(fileinfo_dict[u'last_run_time'])

    return fileinfo_dict

def filetime_to_epoch(filetime):
    return int(filetime / 10000000 - 11644473600)

def filetime_to_human(filetime):
    return str(datetime.utcfromtimestamp(float(filetime) * 1e-7 - 11644473600))
        

def process_header_values(header_dict):
    header_dict[u'prefetch_hash'] = hex(header_dict[u'prefetch_hash']).lstrip(u'0x')
    header_dict[u'exe_name'] = filenameHandler(header_dict[u'exe_name'])
    return header_dict

def parseHeader(buf):
    parsed_header = struct.unpack('<4I60s2I', buf)
    header_dict = dict(zip(header_members, parsed_header))
    return process_header_values(header_dict)

def prefetchCarve(mfile, outfile, output_type=None, system_name=None):
    offset = 0
    while True:
        offset = mfile.find(b'\x53\x43\x43\x41', offset)

        if offset == -1:
            break

        offset -= 4

        version = struct.unpack('<I', mfile[offset:offset + 4])[0]
        if version in prefetch_types:
            header = parseHeader(mfile[offset:offset + 84])
            offset += 84

            try:
                file_info, offset = parse_file_information(header[u'version'], mfile, offset)
                output(header, file_info, outfile, output_type, system_name)
                continue
            except ValueError:
                continue

        offset += 8


def output(header, file_info, outfile, output_type=None, system_name=None):
    if output_type == "tln":
        if not system_name:
            system_name = u''

        o = u'{0}|CARVED_PREFETCH_LAST_RUN_TIME|{1}||{2}-{3}\n'.format(
            file_info[u'last_run_time_epoch'],
            system_name,
            header[u'exe_name'],
            header[u'prefetch_hash'])

    elif output_type == "csv":
        o = u'{0},{1}-{2},{3}\n'.format(
            file_info[u'last_run_time_human'],
            header[u'exe_name'],
            header[u'prefetch_hash'],
            file_info[u'run_count'])

    elif output_type == "mactime":
        o = u'0|{0}-{1} (CARVED_PREFETCH_LAST_RUN_TIME)|run_count: {2}|0|0|0|0|{3}|{3}|{3}|{3}\n'.format(
        header[u'exe_name'],
        header[u'prefetch_hash'],
        file_info[u'run_count'],
        file_info[u'last_run_time_epoch'],
        file_info[u'last_run_time_epoch'],
        file_info[u'last_run_time_epoch'],
        file_info[u'last_run_time_epoch'])

    else:
        o = u'{0} | {1}-{2} | run_count: {3}\n'.format(
            file_info[u'last_run_time_human'],
            header[u'exe_name'],
            header[u'prefetch_hash'],
            file_info[u'run_count'])

    outfile.write(o.encode('utf8', errors='backslashreplace'))


def main():
    p = ArgumentParser()
    p.add_argument('-f', '--file', help='Carve Prefetch files from the given file', required=True)
    p.add_argument('-o', '--outfile', help='Write results to the given file', required=True)
    p.add_argument('-c', '--csv', help='Output results in csv format', action='store_true')
    p.add_argument('-m', '--mactime', help='Output results in mactime format', action='store_true')
    p.add_argument('-t', '--tln', help='Output results in tln format', action='store_true')
    p.add_argument('-s', '--system', help='System name (use with -t)')

    args = p.parse_args()

    with open(args.file, 'rb') as i:
        with contextlib.closing(mmap.mmap(i.fileno(), 0 , access=mmap.ACCESS_READ)) as m:
            with open(args.outfile, 'wb') as o:
                if args.tln:
                    prefetchCarve(m, o, "tln", system_name=args.system)
                elif args.csv:
                    o.write(u'last_run_time,prefetch_file_name,run_count\n')
                    prefetchCarve(m, o, output_type="csv")
                elif args.mactime:
                    prefetchCarve(m, o, output_type="mactime")
                else:
                    prefetchCarve(m, o)


if __name__ == '__main__':
    main()
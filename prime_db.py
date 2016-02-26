#!/usr/bin/env python3

import argparse
from base64 import b64decode
import os
import re

from peewee import SqliteDatabase, Model, TextField, IntegerField
from pyasn1.codec.der import decoder

BULK = 140

RE_OPENSSL_BIT_SIZE = re.compile(r'\((\d+) bit\)')
RE_OPENSSL_GENERATOR = re.compile(r'generator: (\d+) \(')
RE_OPENSSL_PRIME_NUMBER = re.compile(r'prime:(.*?)generator', re.DOTALL)
RE_GNUTLS_GENERATOR = re.compile(r'generator:(.*?)prime:', re.DOTALL)
RE_GNUTLS_PRIME_NUMBER = re.compile(r'prime:(.*?)-----BEGIN', re.DOTALL)
RE_WHITE = re.compile(r'\s+')
RE_DH_PARAMETERS = re.compile(r'(-{5}BEGIN DH PARAMETERS.*?END DH PARAMETERS-{5})', re.DOTALL)
RE_B64_DER = re.compile(r'-{5}BEGIN DH PARAMETERS-{5}\n(.*)\n-{5}END DH PARAMETERS-{5}', re.DOTALL)

db = SqliteDatabase('dhprimes.db')


class Primes(Model):
    integer = TextField()
    generator = TextField()
    bitsize = IntegerField()
    base16 = TextField()
    pem = TextField()
    b64der = TextField()
    full = TextField()

    class Meta:
        database = db


def create_table_if_missing():
    db.create_table(Primes, safe=True)


def parse_gnutls_file(text, f):
    """
    Parse and check validity of all attributes in a GnuTLS-generated DH
    param file since we store it in its entirety.
    """
    regexes = [
        (RE_GNUTLS_GENERATOR, 'base 16 generator'),
        (RE_GNUTLS_PRIME_NUMBER, 'base 16 prime number'),
        (RE_DH_PARAMETERS, 'DH parameters'),
    ]

    raw_data = []
    for regex, name in regexes:
        search = regex.search(text)
        if search:
            raw_data.append(search.group(1))
        else:
            print('ERROR: Could not find {} in {}; skipping'.format(name, f))
            return

    params = {}
    params['generator'] = int(RE_WHITE.sub('', raw_data[0]).replace(':', ''), 16)
    params['pem'] = raw_data[2]
    params['b64der'] = RE_B64_DER.search(raw_data[2]).group(1).replace('\n', '')
    params['base16'] = RE_WHITE.sub('', raw_data[1]).rstrip(':')
    params['full'] = text
    try:
        params['integer'] = int(params['base16'].replace(':', ''), 16)
    except ValueError:
        print('ERROR: Malformed base 16 prime in {}; skipping'.format(f))
        return
    params['bitsize'] = len(bin(params['integer'])[2:])

    # Check PEM cert and compare with data above
    seq, _ = decoder.decode(b64decode(params['b64der']))
    if not int(seq.getComponentByPosition(0)) == params['integer']:
        print('ERROR: PEM integer does not match base16 integer in {}; skipping'.format(f))
        return
    if not int(seq.getComponentByPosition(1)) == params['generator']:
        print('ERROR: PEM generator does not match base16 generator in {}; skipping'.format(f))
        return

    return params


def parse_openssl_file(text, f):
    """
    Parse and check validity of all attributes in an OpenSSL-generated DH
    param file since we store it in its entirety.
    """
    regexes = [
        (RE_OPENSSL_BIT_SIZE, 'bit size'),
        (RE_OPENSSL_GENERATOR, 'generator'),
        (RE_OPENSSL_PRIME_NUMBER, 'base 16 prime number'),
        (RE_DH_PARAMETERS, 'DH parameters'),
    ]

    raw_data = []
    for regex, name in regexes:
        search = regex.search(text)
        if search:
            raw_data.append(search.group(1))
        else:
            print('ERROR: Could not find {} in {}; skipping'.format(name, f))
            return

    params = {}
    params['bitsize'] = int(raw_data[0])
    params['generator'] = int(raw_data[1])
    params['pem'] = raw_data[3]
    params['b64der'] = RE_B64_DER.search(raw_data[3]).group(1).replace('\n', '')
    params['base16'] = RE_WHITE.sub('', raw_data[2])
    params['full'] = text
    try:
        params['integer'] = int(params['base16'].replace(':', ''), 16)
    except ValueError:
        print('ERROR: Malformed base 16 prime in {}; skipping'.format(f))
        return

    # Check bit size matches int size
    if not int(params['bitsize']) == len(bin(params['integer'])[2:]):
        print('ERROR: Bit size does not match integer size in {}; skipping'.format(f))
        return

    # Check PEM cert and compare with data above
    seq, _ = decoder.decode(b64decode(params['b64der']))
    if not int(seq.getComponentByPosition(0)) == params['integer']:
        print('ERROR: PEM integer does not match base16 integer in {}; skipping'.format(f))
        return
    if not int(seq.getComponentByPosition(1)) == params['generator']:
        print('ERROR: PEM generator does not match base16 generator in {}; skipping'.format(f))
        return

    return params


def parse_file(f):
    text = open(f).read()

    if 'DH Parameters' in text and 'BEGIN DH PARAMETERS' in text:
        return parse_openssl_file(text, f)
    elif 'Recommended key length' in text and 'BEGIN DH PARAMETERS' in text:
        return parse_gnutls_file(text, f)


def main():
    p = argparse.ArgumentParser(description='Create/Update SQLite database \
                                             with DH primes generated by OpenSSL.')
    p.add_argument('-i', '--input', dest='in_files',
                   action='store', help='File or directory with DH prime(s)')
    p.add_argument('-o', '--out_db', dest='out_db',
                   action='store', help='Output to database file (default is dhprimes.db)')
    p.add_argument('-p', '--print', dest='print_output',
                   action='store_true', help='Print output instead of creating database')
    args = p.parse_args()

    if not args.in_files:
        p.error('You must specify input file or directory')

    if not os.path.exists(args.in_files):
        p.error('Specified file or directory does not exist')

    all_files = []
    if os.path.isdir(args.in_files):
        for directory, _, files in os.walk(args.in_files):
            if '.git' not in directory:
                all_files.extend(os.path.join(directory, x) for x in files)
    elif os.path.isfile(args.in_files):
        files.append(args.in_files)
    else:
        p.error('Specified input is not a file or a directory')

    create_table_if_missing()

    # Bulk updates of the database to keep memory usage low. Also Peewee/SQLite
    # can't handle more than BULK of these updates in insert_many. It depends
    # on insert size, so BULK is dependent on data size
    updates = []
    with db.atomic():
        for f in all_files:
            params = parse_file(f)
            if params:
                updates.append(params)
            if len(updates) > BULK:
                bulks = len(updates) // BULK
                for idx in range(bulks):
                    Primes.insert_many(updates[idx * BULK:idx * BULK + BULK]).execute()
                updates = updates[bulks * BULK:]
        Primes.insert_many(updates).execute()


if __name__ == '__main__':
    main()

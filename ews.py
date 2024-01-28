#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import os
import time
import codecs
import hashlib
from datetime import datetime
import glob
from moduls.einit import locksocket, ecfg
from moduls.elog import ELog
from moduls.etoolbox import readonecfg
from moduls.ealert import EAlert
from moduls.esend import ESend
import base64
from urllib import parse

name = "EWS Poster Modified"
version = "v1.25"

def dionaea():

    dionaea = EAlert('dionaea', ECFG)

    ITEMS = ['dionaea', 'nodeid', 'sqlitedb', 'malwaredir']
    HONEYPOT = (dionaea.readCFG(ITEMS, ECFG['cfgfile']))

    if 'error_files' in HONEYPOT and HONEYPOT['error_files'] is False:
        print(f"    -> {HONEYPOT['error_files_msg']}. Skip Honeypot.")
        return()

    while True:
        line, download = dionaea.lineSQLITE(HONEYPOT['sqlitedb'])

        if len(line) == 0 or (line == 'false' and download == 'false'):
            break
        if line['remote_host'] == "":
            continue

        for dockerIp in ['remote_host', 'local_host']:
            if '..ffff:' in line[dockerIp]:
                line[dockerIp] = line[dockerIp].split('::ffff:')[1]

        dionaea.data('analyzer_id', HONEYPOT['nodeid']) if 'nodeid' in HONEYPOT else None

        if 'connection_timestamp' in line:
            dionaea.data('timestamp', datetime.utcfromtimestamp(int(line["connection_timestamp"])).strftime('%Y-%m-%d %H:%M:%S'))
            dionaea.data("timezone", time.strftime('%z'))

        dionaea.data('source_address', line['remote_host']) if 'remote_host' in line else None
        dionaea.data('target_address', line['local_host']) if 'local_host' in line else None
        dionaea.data('source_port', line['remote_port']) if 'remote_port' in line else None
        dionaea.data('target_port', line['local_port']) if 'local_port' in line else None
        dionaea.data('source_protokoll', line['connection_transport']) if 'connection_transport' in line else None
        dionaea.data('target_protokoll', line['connection_transport']) if 'connection_transport' in line else None

        dionaea.request('description', 'Network Honeyport Dionaea v0.1.0')

        if 'download_md5_hash' in download and ECFG['send_malware'] is True:
            error, payload = dionaea.malwarecheck(HONEYPOT['malwaredir'], str(download['download_md5_hash']), ECFG['del_malware_after_send'], str(download['download_md5_hash']))
            if (error is True) and (len(payload) <= 5 * 1024) and (len(payload) > 0):
                dionaea.request('binary', payload.decode('utf-8'))
            elif (error is True) and (ECFG["send_malware"] is True) and (len(payload) > 0):
                dionaea.request('largepayload', payload.decode('utf-8'))

        dionaea.adata('hostname', ECFG['hostname'])
        dionaea.adata('externalIP', ECFG['ip_ext'])
        dionaea.adata('internalIP', ECFG['ip_int'])
        dionaea.adata('uuid', ECFG['uuid'])
        dionaea.adata('payload_md5', download['download_md5_hash']) if 'download_md5_hash' in download else None

        if dionaea.buildAlert() == "sendlimit":
            break

    dionaea.finAlert()
    return()

if __name__ == "__main__":

    ECFG = ecfg(name, version)
    locksocket(name, ECFG['logdir'])
    logger = ELog('EMain')

    while True:
        if ECFG["a.ewsonly"] is False:
            ESend(ECFG)

        for honeypot in ECFG["HONEYLIST"]:

            if ECFG["a.modul"]:
                if ECFG["a.modul"] == honeypot:
                    if readonecfg(honeypot.upper(), honeypot, ECFG["cfgfile"]).lower() == "true":
                        eval(honeypot + '()')
                        break
                else:
                    continue

            if readonecfg(honeypot.upper(), honeypot, ECFG["cfgfile"]).lower() == "true":
                eval(honeypot + '()')

        if int(ECFG["a.loop"]) == 0:
            print(" => EWSrun finish.")
            break
        else:
            print(f" => Sleeping for {ECFG['a.loop']} seconds ...")
            time.sleep(int(ECFG["a.loop"]))

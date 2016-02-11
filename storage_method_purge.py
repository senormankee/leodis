#!/usr/bin/env python

from __future__ import unicode_literals

import base64
import csv
import getpass
import json
import logging
import os
import sys
import urllib2

from datetime import datetime
from optparse import OptionParser

def get_logger(_file):
    logger = logging.getLogger(_file)
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter(
        '[%(levelname)s] %(asctime)s - %(name)s - %(message)s')
 
    filename = os.path.basename(_file)
    name = os.path.splitext(filename)[0]
    filename = '{}_{}.log'.format(name, datetime.now().isoformat())
    file_handler = logging.FileHandler(filename=filename)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    print('Logging to {}'.format(filename))
 
    return logger
 
log = get_logger(__file__)

def add_streaming_logger(option, opt, value, parser):
    formatter = logging.Formatter(
        '[%(levelname)s] %(asctime)s - %(name)s - %(message)s')
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(formatter)
    log.addHandler(handler)

def zapi(api_url, url, credentials, method='GET', body=None):
    if url.find('http://') < 0:
        url = api_url + url
    b64credentials = base64.b64encode(":".join(credentials)).strip()
    headers = {'authorization': 'Basic ' + b64credentials}
    if method != 'HEAD':
        headers['accept'] = 'application/json'
    if body:
        headers['content-type'] = 'application/xml'
        
    request = urllib2.Request(url, body, headers)
    request.get_method = lambda: method
    try:
        response = urllib2.urlopen(request)
        if method == 'HEAD':
            return response
        response_body = response.read()
    except urllib2.HTTPError as e:
        log.debug('HTTP method: %s', method)
        log.debug('HTTP url: %s', url)
        log.debug('HTTP body: %s', body)
        raise
    if method == 'DELETE':
        return True
    return json.loads(response_body)

import pprint

def storage_method_purge(api_url, dryrun, user, password):
    storage_doc = zapi(api_url, 'storage', (user, password), 'GET')
    pp = pprint.PrettyPrinter(indent=4)

    for storage in storage_doc['storage']:
        storage_vxid = storage['id']
        for storage_method in storage['method']:
            storage_method_vxid = storage_method['id']
            storage_method_path = "storage/{}/method/{}".format(storage_vxid, storage_method_vxid)
            log.debug("DELETE    {}{}".format(api_url, storage_method_path))
            if not dryrun:
                zapi(api_url, storage_method_path, (user, password), 'DELETE')

def main():
    usage = "usage: %prog [options]"
    parser = OptionParser(usage=usage)
    parser.add_option("-u", "--user", dest="user",
                      help="the username to connect to Vidispine API")
    parser.add_option("-d", "--dryrun", dest="dryrun", default=False, action='store_true',
                      help="dry run executing no Vidispine or local calls")
    parser.add_option("-o", "--output", action="callback", callback=add_streaming_logger,
                      help="view the logging output to the console as well")
    (options, args) = parser.parse_args()

    if not options.user:
        parser.error("option -u: username is not provided")
    
    password = ""
    while not password:
        sys.stdout.write("Enter {}'s password:".format(options.user))
        password = getpass.getpass()
    
    log.info('Executing script as %s with %s', options.user, options)
    
    api_url = 'http://localhost:8080/API/'
    try:
        storage_method_purge(api_url, options.dryrun, options.user, password)
    except Exception as e:
        log.exception(e)
        raise

if __name__ == "__main__":
    main()

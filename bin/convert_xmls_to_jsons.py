#!/usr/bin/env python

"""Produce the json reference files which will be compared with converted xml files in
the test suite
"""

import os
import logging
import json


#ensure this directory is on pythohpath, so conf can get imported
fp = os.path.abspath(__file__)
this_dir = os.path.dirname(fp)
import sys
sys.path.append(fp)
print (sys.path)

from conf import (
    clear_dir, JSON_DATA_DIR, XML_DATA_DIR, PROJECT_DIR,
    ConversionFailureError, convert_to_json
)


logging.basicConfig()
logger = logging.getLogger()
logger.setLevel(logging.INFO)


def main():
    clear_dir(JSON_DATA_DIR)

    for afile in os.listdir(XML_DATA_DIR):
        src = os.path.join(XML_DATA_DIR, afile)
        fn = os.path.split(src)[1]
        try:
            jsn = convert_to_json (src)
        except ConversionFailureError:
            logger.error('failed to convert {}'.format(fn))
        else:
            write_json(jsn, afile)
            logger.info('..persisted {} to .json  '.format(fn))


def get_json_target(afile):
     fn = os.path.splitext(afile)[0]
     return os.path.join(JSON_DATA_DIR, '{}.json'.format(fn))


def write_json(jsn, afile):
    tgt = get_json_target(afile)
    with open(tgt, 'w') as fjson:
        fjson.write(jsn)


if __name__ == '__main__':
    main()

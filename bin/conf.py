import os
import shutil
import json


fp = os.path.abspath(__file__)
PROJECT_DIR = os.path.dirname(os.path.dirname(fp))
import sys
sys.path.append(PROJECT_DIR)

from python_kemptech_api.api_xml  import parse_to_dict


DATA_DIR = os.path.join(PROJECT_DIR, 'tests','integration','data')
XML_DATA_DIR = os.path.join(DATA_DIR, 'xml')
JSON_DATA_DIR = os.path.join(DATA_DIR, 'json')


def clear_dir(adir):
    shutil.rmtree(adir, ignore_errors=True)
    os.makedirs(adir)


class ConversionFailureError(Exception):
    pass


def convert_to_dict(src):
    """ converts the content of source xml file to the a dict """

    with open(src) as fxml:
        xml = fxml.read()
        try:
            return parse_to_dict(xml)
        except:
            return ConversionFailureError()


def convert_to_json(src):
    d = convert_to_dict(src)
    return json.dumps(d)

import os
import json

from bin.conf import (JSON_DATA_DIR, XML_DATA_DIR,
    convert_to_dict
    )


class CompareError(Exception):
    pass


def test_all():
    """ compare  the output from converting the xml files with the
    reference json files"""
    errors = []

    for afile in os.listdir(XML_DATA_DIR):
        print ('Looking at {}'.format(afile))
        xml_src = os.path.join(XML_DATA_DIR, afile)
        json_src= os.path.splitext(afile)[0]
        json_src = os.path.join(JSON_DATA_DIR, '{}.json'.format(json_src))

        converted_dict = convert_to_dict(xml_src)

        with open(json_src) as f:
            reference_jsn = f.read()
            reference_dict = json.loads(reference_jsn)
            assert isinstance(reference_dict, (dict, list))

        try:
            compare (reference_dict, converted_dict)
        except CompareError:
            errors.append(afile)

    if errors:
        print('The following failed to match')
        for e in errors:
            print('..{}'.format(e))
        assert False, 'errors found'


def compare(reference, converted):
    if ordered(reference) != ordered(converted):
        raise CompareError


def ordered(obj):
    if isinstance(obj, dict):
        return sorted((k, ordered(v)) for k, v in obj.items())
    elif isinstance(obj, list):
        return sorted(ordered(x) for x in obj)
    else:
        return obj


"""Encapsulate the awful XML response and provide helpful functions."""

import xmltodict


def get_success_msg(xml):
    return str(_get_xml_field(xml, "Success"))


def get_error_msg(xml):
    return str(_get_xml_field(xml, "Error"))


def is_successful(xml):
    """Return True if xml response contains a success, else false."""
    return bool(get_success_msg(xml))


def get_data_field(xml, field):
    """Get the value of a field in the 'Data' part of the LM's XML"""
    value = _get_xml_field(xml, "Data", data_field=field)
    return value or ""


def get_data(xml):
    """Return the 'Data' entry from LM's XML as a dict"""
    success_xml_entry = _get_xml_field(xml, "Success")
    try:
        data = (success_xml_entry['Data']
                if success_xml_entry['Data'] is not None else {})
    except (KeyError, TypeError):
        data = {}
    return data


def parse_to_dict(xml):
    """Return the XML as an OrderedDict."""
    try:
        return xmltodict.parse(xml)
    except xmltodict.expat.ExpatError:
        pass


def _get_xml_field(xml, field, data_field=None):
    """return the string specified, or None if not present"""
    try:
        xml_dict = xmltodict.parse(xml)
        try:
            response_dict = xml_dict["Response"]
            if data_field is None:
                msg = response_dict[field]
            else:
                data = response_dict["Success"][field]
                msg = data[data_field]
            return msg
        except KeyError:
            return {}
    except xmltodict.expat.ExpatError:
        return {}

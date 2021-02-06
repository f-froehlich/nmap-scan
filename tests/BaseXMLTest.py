from xml.etree.ElementTree import ElementTree

import pytest
from lxml import etree

from nmap_scan.Exceptions.NmapDictParserException import NmapDictParserException
from nmap_scan.Exceptions.NmapXMLParserException import NmapXMLParserException


@pytest.mark.parsing
class BaseXMLTest:

    def create_instance(self, xml):
        raise Exception('Must be override create_instance')

    def get_all_files(self):
        raise Exception('Must be override get_all_files')

    def get_all_invalid_files(self):
        raise Exception('Must be override get_all_invalid_files')

    def create_xml(self, filepath):
        parser = etree.XMLParser()
        et = ElementTree()
        return et.parse(source=filepath, parser=parser)

    @pytest.mark.xml
    def test_set_xml(self):
        for filepath in self.get_all_files():
            xml = self.create_xml(filepath)
            e = self.create_instance(xml)

            assert xml == e.get_xml()

    @pytest.mark.xml
    def test_dict_to_xml(self):
        for filepath in self.get_all_files():
            xml = self.create_xml(filepath)
            e1 = self.create_instance(xml)
            if "dict_to_xml" in dir(e1):
                e2 = self.create_instance(e1.dict_to_xml(dict(e1)))
                assert e1.equals(e2)

    @pytest.mark.xml
    def test_from_dict(self):
        for filepath in self.get_all_files():
            xml = self.create_xml(filepath)
            e1 = self.create_instance(xml)
            if "from_dict" in dir(e1):
                e2 = e1.from_dict(dict(e1))
                assert e1.equals(e2)

    @pytest.mark.invalidXML
    @pytest.mark.xml
    def test_error_on_invalid_xml(self):

        for filepath in self.get_all_invalid_files():
            with pytest.raises(NmapXMLParserException) as excinfo:
                xml = self.create_xml(filepath)
                e = self.create_instance(xml)

    @pytest.mark.invalidXML
    @pytest.mark.xml
    def test_error_on_from_dict(self):
        valid_instance = self.create_instance(self.create_xml(self.get_all_files()[0]))

        if "from_dict" in dir(valid_instance):
            with pytest.raises(NmapDictParserException) as excinfo:
                valid_instance.from_dict(dict([]))

    @pytest.mark.invalidXML
    @pytest.mark.xml
    def test_error_on_dict_to_xml(self):
        valid_instance = self.create_instance(self.create_xml(self.get_all_files()[0]))

        if "dict_to_xml" in dir(valid_instance):
            with pytest.raises(NmapDictParserException) as excinfo:
                valid_instance.dict_to_xml(dict([]))

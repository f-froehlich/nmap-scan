from xml.etree.ElementTree import ElementTree

import pytest


@pytest.mark.parsing
class BaseXMLTest:

    def create_instance(self, xml):
        raise Exception('Must be override create_instance')

    def get_all_files(self):
        raise Exception('Must be override get_all_files')

    def create_xml(self, filepath):
        et = ElementTree()
        return et.parse(source=filepath)

    @pytest.mark.xml
    def test_set_xml(self):
        for filepath in self.get_all_files():
            xml = self.create_xml(filepath)
            e = self.create_instance(xml)

            assert xml == e.get_xml()
import pytest

from nmap_scan.Scripts.SSLEnumCiphers import SSLEnumCiphersCipher, SSLEnumCiphersProtocol
from tests.BaseXMLTest import BaseXMLTest


@pytest.mark.script
@pytest.mark.cipher
class TestSSLEnumCiphersCipher(BaseXMLTest):

    def create_instance(self, xml):
        return SSLEnumCiphersProtocol(xml)

    def get_all_files(self):
        return ['testdata/Scripts/SSLEnumCiphers/Protocol-1.xml', 'testdata/Scripts/SSLEnumCiphers/Protocol-2.xml',
                'testdata/Scripts/SSLEnumCiphers/Protocol-3.xml']

    @pytest.mark.parametrize(("filepath", "expected"), [('testdata/Scripts/SSLEnumCiphers/Protocol-1.xml', 'tlsv1.2'),
                                                        ('testdata/Scripts/SSLEnumCiphers/Protocol-2.xml', 'tlsv1.3'),
                                                        ('testdata/Scripts/SSLEnumCiphers/Protocol-3.xml', 'tlsv1.2')
                                                        ])
    def test_protocol_version(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_protocol_version()

    @pytest.mark.parametrize(("filepath", "expected"), [('testdata/Scripts/SSLEnumCiphers/Protocol-1.xml', 'server'),
                                                        ('testdata/Scripts/SSLEnumCiphers/Protocol-2.xml', 'client'),
                                                        ('testdata/Scripts/SSLEnumCiphers/Protocol-3.xml', 'server')
                                                        ])
    def test_cipher_preference(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        assert expected == e.get_cipher_preference()

    @pytest.mark.parametrize(("filepath", "ciphers"), [
        ('testdata/Scripts/SSLEnumCiphers/Protocol-1.xml',
         ['testdata/Scripts/SSLEnumCiphers/Cipher-1.xml', 'testdata/Scripts/SSLEnumCiphers/Cipher-2.xml']),
        ('testdata/Scripts/SSLEnumCiphers/Protocol-2.xml', ['testdata/Scripts/SSLEnumCiphers/Cipher-1.xml']),
    ])
    def test_ciphers(self, filepath, ciphers):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)
        cipher_instances = []
        for c in ciphers:
            xml = self.create_xml(c)
            cipher_instances.append(SSLEnumCiphersCipher(xml))

        assert len(cipher_instances) == len(e.get_ciphers())

        for existing_cipher in e.get_ciphers():
            exist = False
            for c in cipher_instances:
                if existing_cipher.equals(c):
                    assert not exist
                    exist = True
            assert exist

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Scripts/SSLEnumCiphers/Protocol-1.xml', 'NULL'),
        ('testdata/Scripts/SSLEnumCiphers/Protocol-2.xml', 'FOO'),
        ('testdata/Scripts/SSLEnumCiphers/Protocol-3.xml', 'NULL'),
    ])
    def test_compressors(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)

        assert expected == e.get_compressor()

    @pytest.mark.parametrize(("filepath", "expected"), [
        ('testdata/Scripts/SSLEnumCiphers/Protocol-1.xml', 'D'),
        ('testdata/Scripts/SSLEnumCiphers/Protocol-2.xml', 'A'),
        ('testdata/Scripts/SSLEnumCiphers/Protocol-3.xml', 'D')
    ])
    def test_get_least_strength(self, filepath, expected):
        xml = self.create_xml(filepath)
        e = self.create_instance(xml)

        assert expected == e.get_least_strength()

    @pytest.mark.parametrize(("filepath1", "filepath2", "expected"), [
        ('testdata/Scripts/SSLEnumCiphers/Protocol-1.xml', 'testdata/Scripts/SSLEnumCiphers/Protocol-1.xml', True),
        ('testdata/Scripts/SSLEnumCiphers/Protocol-1.xml', 'testdata/Scripts/SSLEnumCiphers/Protocol-2.xml', False),
        ('testdata/Scripts/SSLEnumCiphers/Protocol-1.xml', 'testdata/Scripts/SSLEnumCiphers/Protocol-3.xml', False),
        ('testdata/Scripts/SSLEnumCiphers/Protocol-1.xml', 'testdata/Scripts/SSLEnumCiphers/Protocol-4.xml', False),
        ('testdata/Scripts/SSLEnumCiphers/Protocol-2.xml', 'testdata/Scripts/SSLEnumCiphers/Protocol-1.xml', False),
        ('testdata/Scripts/SSLEnumCiphers/Protocol-2.xml', 'testdata/Scripts/SSLEnumCiphers/Protocol-2.xml', True),
        ('testdata/Scripts/SSLEnumCiphers/Protocol-2.xml', 'testdata/Scripts/SSLEnumCiphers/Protocol-3.xml', False),
        ('testdata/Scripts/SSLEnumCiphers/Protocol-2.xml', 'testdata/Scripts/SSLEnumCiphers/Protocol-4.xml', False),
        ('testdata/Scripts/SSLEnumCiphers/Protocol-3.xml', 'testdata/Scripts/SSLEnumCiphers/Protocol-1.xml', False),
        ('testdata/Scripts/SSLEnumCiphers/Protocol-3.xml', 'testdata/Scripts/SSLEnumCiphers/Protocol-2.xml', False),
        ('testdata/Scripts/SSLEnumCiphers/Protocol-3.xml', 'testdata/Scripts/SSLEnumCiphers/Protocol-3.xml', True),
        ('testdata/Scripts/SSLEnumCiphers/Protocol-3.xml', 'testdata/Scripts/SSLEnumCiphers/Protocol-4.xml', False),
        ('testdata/Scripts/SSLEnumCiphers/Protocol-4.xml', 'testdata/Scripts/SSLEnumCiphers/Protocol-1.xml', False),
        ('testdata/Scripts/SSLEnumCiphers/Protocol-4.xml', 'testdata/Scripts/SSLEnumCiphers/Protocol-2.xml', False),
        ('testdata/Scripts/SSLEnumCiphers/Protocol-4.xml', 'testdata/Scripts/SSLEnumCiphers/Protocol-3.xml', False),
        ('testdata/Scripts/SSLEnumCiphers/Protocol-4.xml', 'testdata/Scripts/SSLEnumCiphers/Protocol-4.xml', True),
    ])
    def test_equals(self, filepath1, filepath2, expected):
        xml1 = self.create_xml(filepath1)
        e1 = self.create_instance(xml1)
        xml2 = self.create_xml(filepath2)
        e2 = self.create_instance(xml2)

        assert expected == e1.equals(e2)

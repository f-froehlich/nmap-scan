import pytest

from nmap_scan.Exceptions.LogicException import LogicException
from nmap_scan.Scripts.SSLEnumCiphers import CipherCompare


@pytest.mark.script
class TestCipherCompare:

    @pytest.mark.parametrize(("strength", "expected"),
                             [('a', 1), ('A', 1), ('b', 2), ('B', 2), ('c', 3), ('C', 3), ('d', 4), ('D', 4), ('e', 5),
                              ('E', 5), ('f', 6), ('F', 6)])
    def test_map_strength(self, strength, expected):
        assert expected == CipherCompare.map_strength(strength)

    @pytest.mark.parametrize("strength", ['X', 'foo', 'bar'])
    def test_map_strength_raise_error_on_unknown_strength(self, strength):
        with pytest.raises(LogicException) as excinfo:
            CipherCompare.map_strength(strength)
        assert 'Invalid strength "{strength}" detected. Must be A-F'.format(strength=strength) in str(excinfo.value)

    @pytest.mark.parametrize(("strength", "expected"), [(1, 'A'), (2, 'B'), (3, 'C'), (4, 'D'), (5, 'E'), (6, 'F'), ])
    def test_reverse_map_strength(self, strength, expected):
        assert expected == CipherCompare.reverse_map_strength(strength)

    @pytest.mark.parametrize("strength", list(range(7, 10)) + [0, -1])
    def test_reverse_map_strength_raise_error_on_unknown_strength(self, strength):
        with pytest.raises(LogicException) as excinfo:
            CipherCompare.reverse_map_strength(strength)
        assert 'Invalid strength "{strength}" detected. Must be A-F'.format(strength=strength) in str(excinfo.value)

    @pytest.mark.parametrize(("a", "b", 'expected'),
                             [
                                 ('a', 'a', False), ('a', 'b', True), ('a', 'c', True), ('a', 'd', True),
                                 ('a', 'e', True), ('a', 'f', True),
                                 ('b', 'a', False), ('b', 'b', False), ('b', 'c', True), ('b', 'd', True),
                                 ('b', 'e', True), ('b', 'f', True),
                                 ('c', 'a', False), ('c', 'b', False), ('c', 'c', False), ('c', 'd', True),
                                 ('c', 'e', True), ('c', 'f', True),
                                 ('d', 'a', False), ('d', 'b', False), ('d', 'c', False), ('d', 'd', False),
                                 ('d', 'e', True), ('d', 'f', True),
                                 ('e', 'a', False), ('e', 'b', False), ('e', 'c', False), ('e', 'd', False),
                                 ('e', 'e', False), ('e', 'f', True),
                                 ('f', 'a', False), ('f', 'b', False), ('f', 'c', False), ('f', 'd', False),
                                 ('f', 'e', False), ('f', 'f', False),
                             ])
    def test_a_lower_b(self, a, b, expected):
        assert expected == CipherCompare.a_lower_b(a, b)
        assert expected == CipherCompare.a_better_b(a, b)

    @pytest.mark.parametrize(("a", "b", 'expected'),
                             [
                                 ('a', 'a', True), ('a', 'b', True), ('a', 'c', True), ('a', 'd', True),
                                 ('a', 'e', True), ('a', 'f', True),
                                 ('b', 'a', False), ('b', 'b', True), ('b', 'c', True), ('b', 'd', True),
                                 ('b', 'e', True), ('b', 'f', True),
                                 ('c', 'a', False), ('c', 'b', False), ('c', 'c', True), ('c', 'd', True),
                                 ('c', 'e', True), ('c', 'f', True),
                                 ('d', 'a', False), ('d', 'b', False), ('d', 'c', False), ('d', 'd', True),
                                 ('d', 'e', True), ('d', 'f', True),
                                 ('e', 'a', False), ('e', 'b', False), ('e', 'c', False), ('e', 'd', False),
                                 ('e', 'e', True), ('e', 'f', True),
                                 ('f', 'a', False), ('f', 'b', False), ('f', 'c', False), ('f', 'd', False),
                                 ('f', 'e', False), ('f', 'f', True),
                             ])
    def test_a_lower_equals_b(self, a, b, expected):
        assert expected == CipherCompare.a_lower_equals_b(a, b)
        assert expected == CipherCompare.a_better_equals_b(a, b)

    @pytest.mark.parametrize(("a", "b", 'expected'),
                             [
                                 ('a', 'a', False), ('a', 'b', False), ('a', 'c', False), ('a', 'd', False),
                                 ('a', 'e', False), ('a', 'f', False),
                                 ('b', 'a', True), ('b', 'b', False), ('b', 'c', False), ('b', 'd', False),
                                 ('b', 'e', False), ('b', 'f', False),
                                 ('c', 'a', True), ('c', 'b', True), ('c', 'c', False), ('c', 'd', False),
                                 ('c', 'e', False), ('c', 'f', False),
                                 ('d', 'a', True), ('d', 'b', True), ('d', 'c', True), ('d', 'd', False),
                                 ('d', 'e', False), ('d', 'f', False),
                                 ('e', 'a', True), ('e', 'b', True), ('e', 'c', True), ('e', 'd', True),
                                 ('e', 'e', False), ('e', 'f', False),
                                 ('f', 'a', True), ('f', 'b', True), ('f', 'c', True), ('f', 'd', True),
                                 ('f', 'e', True), ('f', 'f', False),
                             ])
    def test_a_greater_b(self, a, b, expected):
        assert expected == CipherCompare.a_grater_b(a, b)
        assert expected == CipherCompare.a_worse_b(a, b)

    @pytest.mark.parametrize(("a", "b", 'expected'),
                             [
                                 ('a', 'a', True), ('a', 'b', False), ('a', 'c', False), ('a', 'd', False),
                                 ('a', 'e', False), ('a', 'f', False),
                                 ('b', 'a', True), ('b', 'b', True), ('b', 'c', False), ('b', 'd', False),
                                 ('b', 'e', False), ('b', 'f', False),
                                 ('c', 'a', True), ('c', 'b', True), ('c', 'c', True), ('c', 'd', False),
                                 ('c', 'e', False), ('c', 'f', False),
                                 ('d', 'a', True), ('d', 'b', True), ('d', 'c', True), ('d', 'd', True),
                                 ('d', 'e', False), ('d', 'f', False),
                                 ('e', 'a', True), ('e', 'b', True), ('e', 'c', True), ('e', 'd', True),
                                 ('e', 'e', True), ('e', 'f', False),
                                 ('f', 'a', True), ('f', 'b', True), ('f', 'c', True), ('f', 'd', True),
                                 ('f', 'e', True), ('f', 'f', True),
                             ])
    def test_a_greater_equals_b(self, a, b, expected):
        assert expected == CipherCompare.a_grater_equals_b(a, b)
        assert expected == CipherCompare.a_worse_equals_b(a, b)

    @pytest.mark.parametrize(("a", "b", 'expected'),
                             [
                                 ('a', 'a', True), ('a', 'b', False), ('a', 'c', False), ('a', 'd', False),
                                 ('a', 'e', False), ('a', 'f', False),
                                 ('b', 'a', False), ('b', 'b', True), ('b', 'c', False), ('b', 'd', False),
                                 ('b', 'e', False), ('b', 'f', False),
                                 ('c', 'a', False), ('c', 'b', False), ('c', 'c', True), ('c', 'd', False),
                                 ('c', 'e', False), ('c', 'f', False),
                                 ('d', 'a', False), ('d', 'b', False), ('d', 'c', False), ('d', 'd', True),
                                 ('d', 'e', False), ('d', 'f', False),
                                 ('e', 'a', False), ('e', 'b', False), ('e', 'c', False), ('e', 'd', False),
                                 ('e', 'e', True), ('e', 'f', False),
                                 ('f', 'a', False), ('f', 'b', False), ('f', 'c', False), ('f', 'd', False),
                                 ('f', 'e', False), ('f', 'f', True),
                             ])
    def test_a_equals_b(self, a, b, expected):
        assert expected == CipherCompare.a_equals_b(a, b)

    @pytest.mark.parametrize(("a", "b", 'expected'),
                             [
                                 ('a', 'a', False), ('a', 'b', True), ('a', 'c', True), ('a', 'd', True),
                                 ('a', 'e', True), ('a', 'f', True),
                                 ('b', 'a', True), ('b', 'b', False), ('b', 'c', True), ('b', 'd', True),
                                 ('b', 'e', True), ('b', 'f', True),
                                 ('c', 'a', True), ('c', 'b', True), ('c', 'c', False), ('c', 'd', True),
                                 ('c', 'e', True), ('c', 'f', True),
                                 ('d', 'a', True), ('d', 'b', True), ('d', 'c', True), ('d', 'd', False),
                                 ('d', 'e', True), ('d', 'f', True),
                                 ('e', 'a', True), ('e', 'b', True), ('e', 'c', True), ('e', 'd', True),
                                 ('e', 'e', False), ('e', 'f', True),
                                 ('f', 'a', True), ('f', 'b', True), ('f', 'c', True), ('f', 'd', True),
                                 ('f', 'e', True), ('f', 'f', False),
                             ])
    def test_a_not_equals_b(self, a, b, expected):
        assert expected == CipherCompare.a_not_equals_b(a, b)

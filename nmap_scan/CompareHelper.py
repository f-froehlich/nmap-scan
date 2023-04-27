#  nmap-scan
#
#  Nmap wrapper for python
#
#  Copyright (c) 2020 Fabian Fröhlich <mail@nmap-scan.de> <https://nmap-scan.de>
#
#
#  This program is free software: you can redistribute it and/or modify
#  it under the terms of the GNU Affero General Public License as
#  published by the Free Software Foundation, either version 3 of the
#  License, or (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU Affero General Public License for more details.
#
#  You should have received a copy of the GNU Affero General Public License
#  along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
#  For all license terms see README.md and LICENSE Files in root directory of this Project.
#
#  Checkout this project on github <https://github.com/f-froehlich/nmap-scan>
#  and also my other projects <https://github.com/f-froehlich>


def compare_script_maps(m1, m2):
    if len(m1) != len(m2):
        return False

    for own_script_key in m1:
        own_script = m1[own_script_key]
        other_script = m2.get(own_script_key, None)

        if None is  other_script \
                or (isinstance(own_script, list) and not isinstance(other_script, list)) \
                or (not isinstance(own_script, list) and isinstance(other_script, list)):
            return False

        if isinstance(own_script, list):

            return compare_lists_equal(own_script, other_script)
        else:
            if not own_script.equals(other_script):
                return False

    return True


def compare_lists_equal(l1, l2):
    if len(l1) != len(l2):
        return False

    for e1 in l1:
        exist = False
        for e2 in l2:
            if e1.equals(e2):
                exist = True
                break
        if not exist:
            return False

    for e2 in l2:
        exist = False
        for e1 in l1:
            if e1.equals(e2):
                exist = True
                break
        if not exist:
            return False

    return True


def compare_lists(l1, l2):
    if len(l1) != len(l2):
        return False

    for e1 in l1:
        if e1 not in l2:
            return False

    for e2 in l2:
        if e2 not in l1:
            return False

    return True

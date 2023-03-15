#!/usr/bin/python3
#   Copyright 2023 David Malcolm <dmalcolm@redhat.com>
#   Copyright 2023 Red Hat, Inc.
#
#   This library is free software; you can redistribute it and/or
#   modify it under the terms of the GNU Lesser General Public
#   License as published by the Free Software Foundation; either
#   version 2.1 of the License, or (at your option) any later version.
#
#   This library is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
#   Lesser General Public License for more details.
#
#   You should have received a copy of the GNU Lesser General Public
#   License along with this library; if not, write to the Free Software
#   Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301
#   USA

import argparse
from pathlib import Path
from pprint import pprint
import sys

import sarif.loader

class SarifDumper:
    pass

class GccStyleDumper(SarifDumper):
    """
    Print SARIF results in a form that mimics GCC diagnostic output format.
    """
    def __init__(self, dst_file, base_path):
        self.dst_file = dst_file
        self.base_path = base_path
        self.last_logical_location = None

    def dump_sarif_file(self, sarif_file):
        for result in sarif_file.get_results():
            self.dump_sarif_result(result)

    def dump_sarif_result(self, result):
        """
        Handle a §3.27 result object
        """
        # §3.27.12 locations property
        if 'locations' in result:
            loc = result['locations'][0]
            self.write_location(loc)

        # §3.27.10 level property
        if 'level' in result:
            self.write('%s: ' % result['level'])

        # §3.27.11 message property
        self.write('%s' % result['message']['text'])

        # §3.27.8 taxa property
        if 'taxa' in result:
            for rdr in result['taxa']:
                self.write_reporting_descriptor_reference(rdr)

        # §3.27.5 ruleId property
        if 'ruleId' in result:
            self.write(' [%s]' % result['ruleId'])
        self.writeln()

        # §3.27.18 codeFlows property
        if 'codeFlows' in result:
            self.write_code_flow(result['codeFlows'][0])

        #pprint(result)

    def write_location(self, location):
        """
        Handle a §3.28 location object.
        """
        if 'logicalLocations' in location:
            if location['logicalLocations']:
                self.write_logical_location(location['logicalLocations'][0])
        if 'physicalLocation' in location:
            self.write_physical_location(location['physicalLocation'])

    def write_logical_location(self, logicalLocation):
        """
        Handle a §3.33 logicalLocation object.
        """
        if logicalLocation == self.last_logical_location:
            return
        self.last_logical_location = logicalLocation
        if logicalLocation['kind'] == 'function':
            self.write("In function '%s':"
                       % logicalLocation['fullyQualifiedName'])
            self.writeln()

    def write_physical_location(self, physicalLocation):
        """
        Handle a §3.29 physicalLocation object.

        Prepend the URI from the SARIF with self.base_path to make it easy
        to click on the diagnostic in Emacs's compilation buffer.
        """
        filename = physicalLocation['artifactLocation']['uri']
        region = physicalLocation['region']
        self.write('%s:%i:' % (Path(self.base_path, filename),
                               region['startLine']))
        if 'startColumn' in region:
            self.write('%i:' % physicalLocation['region']['startColumn'])
        self.write(' ')

    def write_reporting_descriptor_reference(self, rdr):
        """
        Handle a §3.52 reportingDescriptorReference object.
        """
        if 'toolComponent' in rdr:
            if rdr['toolComponent']['name'] == 'cwe':
                self.write(' [CWE-%s]' % rdr['id'])

    def write_code_flow(self, codeFlow):
        """
        Handle a §3.36 codeFlow object.
        """
        self.write_thread_flow(codeFlow['threadFlows'][0])

    def write_thread_flow(self, threadFlow):
        """
        Handle a §3.37 threadFlow object.
        """
        for idx, loc in enumerate(threadFlow['locations']):
            self.write_thread_flow_location(idx, loc)

    def write_thread_flow_location(self, idx, threadFlowLocation):
        """
        Handle a §3.38 threadFlowLocation object.
        """
        self.write_location(threadFlowLocation['location'])
        self.write('(%i) ' % (idx + 1))
        self.write(threadFlowLocation['location']['message']['text'])
        self.writeln()

    def write(self, text):
        self.dst_file.write(text)

    def writeln(self):
        self.write('\n')

def main():
    parser = argparse.ArgumentParser(
        description = ('Load SARIF file(s) at or below a PATH'
                       ' and dump to stdout in a GCC-like format'))
    parser.add_argument('path', type=Path)
    args = parser.parse_args()
    #print(args)

    for sarif_path in Path(args.path).glob('**/*.sarif'):
        #print(sarif_path)
        sarif_file = sarif.loader.load_sarif_file(sarif_path)
        dumper = GccStyleDumper(sys.stdout, sarif_path.parent)
        dumper.dump_sarif_file(sarif_file)

if __name__ == '__main__':
    main()

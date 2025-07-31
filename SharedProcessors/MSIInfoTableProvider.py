#!/usr/local/autopkg/python
#
#
# Created by Jamie Piperberg (jamie.piperberg@gmail.com)
# Based heavily on 
# https://github.com/autopkg/hansen-m-recipes/blob/master/SharedProcessors/MSIInfoVersionProvider.py

# and https://github.com/autopkg/autopkg/blob/master/Code/autopkglib/URLTextSearcher.py
#
# Retreives user specified table from msi file and searches with a regex for desired output
# Requires installation of msitools, and availablility of 'msiinfo'
# Run: brew install msitools - https://wiki.gnome.org/msitools

from __future__ import absolute_import

import os
import subprocess
import sys
import platform
import re

from autopkglib import Processor, ProcessorError

MATCH_MESSAGE = "Found matching text"
NO_MATCH_MESSAGE = "No match found on URL"

__all__ = ["MSIInfoTableProvider"]


class MSIInfoTableProvider(Processor):
    description = "Retreives requested property of a .msi file using msiinfo.'"
    input_variables = {
        "msi_path": {
            "required": False,
            "description": "Path to the .msi, defaults to %pathname%",
        },
        "msiinfo_path": {
            "required": False,
            "description": "Path to the msiinfo binary, defaults to /usr/local/bin/msiinfo",
        },
        "msiinfo_table": {
            "required": True,
            "description": "table to be retrieved",
        },
        "msiinfo_regex": {
            "required": True,
            "description": "regex to match",
        },
        "result_output_var_name": {
            "description": (
                "The name of the output variable that is returned "
                "by the match. If not specified then a default of "
                '"match" will be used.'
            ),
            "required": False,
            "default": "match",
        },
    }
    output_variables = { 
       "result_output_var_name": {
          "description": (
              "First matched sub-pattern from input found on the fetched "
              "URL. Note the actual name of variable depends on the input "
              'variable "result_output_var_name" or is assigned a default of '
              '"match."'
          )
      }
    }

    __doc__ = description

    def main(self):

        # Set default path to msiinfo
        if 'arm' in platform.processor():
            msiinfo_default_path = os.path.abspath("/opt/homebrew/bin/msiinfo")
        else:
            msiinfo_default_path = os.path.abspath("/usr/local/bin/msiinfo")

        # Set MSIINFO variable to input variable or default path
        MSIINFO = self.env.get('msiinfo_path', msiinfo_default_path)

        # Set msi_path from input
        msi_path = self.env.get('msi_path')
        verbosity = self.env.get('verbose', 0)

        if subprocess.call(["type", MSIINFO], stdout=subprocess.PIPE, stderr=subprocess.PIPE) != 0:
            self.output("msiinfo executable not found at %s" % MSIINFO)
            raise ProcessorError(
                f"MSIInfoTableProvider: msiinfo executable not found. Need to install using `brew install msitools`"
            )
            sys.exit(1)

        if not os.path.isfile(msi_path):
            self.output("MSI file path not found: %s" % msi_path)
            sys.exit(1)

        self.output("Evauluating: %s" % msi_path)
        table = self.env.get('msiinfo_table')
        regex = self.env.get('msiinfo_regex')
        if not table:
            self.output("table name not found")
            sys.exit(1)
        cmd = [MSIINFO, 'export', msi_path, table]
        # self.output(" ".join(cmd))
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (stdout, stderr) = proc.communicate()

        read_msiinfo_table = ""

        regex_match = re.search(regex, stdout.decode())
        re_match, re_group = (regex_match.group(regex_match.lastindex or 0), regex_match.groupdict())
        output_var_name = self.env["result_output_var_name"]

        # favor a named group over a normal group match
        if output_var_name not in re_group.keys():
            re_group[output_var_name] = re_match

        self.output_variables = {}
        for key in re_group.keys():
            self.env[key] = re_group[key]
            self.output(f"{MATCH_MESSAGE} ({key}): {self.env[key]}")
            self.output_variables[key] = {
                "description": "Matched regular expression group"
            }

if __name__ == '__main__':
    processor = MSIInfoTableProvider()
    processor.execute_shell()
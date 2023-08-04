#!/usr/local/autopkg/python
#
#
# Created by Jamie Piperberg (jamie.piperberg@gmail.com)
# Based heavily on 
# https://github.com/autopkg/hansen-m-recipes/blob/master/SharedProcessors/MSIInfoVersionProvider.py
#
# Retreives the version of a .msi file using the msiinfo binary.
# Requires installation of msitools, and availablility of 'msiinfo'
# Run: brew install msitools - https://wiki.gnome.org/msitools

from __future__ import absolute_import

import os
import subprocess
import sys
import platform

from autopkglib import Processor, ProcessorError

__all__ = ["MSIInfoPropertyProvider"]


class MSIInfoPropertyProvider(Processor):
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
        "msiinfo_property": {
            "required": True,
            "description": "property to be retrieved",
        },
    }
    output_variables = {
        "msi_property": {
            "description": (
                "Retrieved property info"
            ),
        },
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
                f"MSIInfoPropertyProvider: msiinfo executable not found. Need to install using `brew install msitools`"
            )
            sys.exit(1)

        if not os.path.isfile(msi_path):
            self.output("MSI file path not found: %s" % msi_path)
            sys.exit(1)

        self.output("Evauluating: %s" % msi_path)
        cmd = [MSIINFO, 'export', msi_path, 'Property']
        # self.output(" ".join(cmd))
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (stdout, stderr) = proc.communicate()

        read_msiinfo_property = ""
        # self.output(stdout)
        for line in stdout.decode().split("\n"):
            if line.startswith(self.env['msiinfo_property']):
                read_msiinfo_property = line.split("\t")[1].strip("\r")
        if verbosity > 1:
            if stderr:
                self.output('msiinfo Errors: %s' % stderr)
        if read_msiinfo_property == "":
            self.output("Could not find version in msi file. Please open a bug.")
        self.env['msi_property'] = read_msiinfo_property
        self.output("Found property: %s" % (self.env['msi_property']))

if __name__ == '__main__':
    processor = MSIInfoPropertyProvider()
    processor.execute_shell()
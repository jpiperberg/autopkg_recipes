#!/usr/local/autopkg/python
#
# Created by Jamie Piperberg (jamie.piperberg@gmail.com)
#
# Verifies the signature of a downloaded PE (EXE/SYS/DLL/etc), CAB, CAT, MSI and APPX files,
# as well as script files with extensions .ps1, .ps1xml, .psc1, .psd1, .psm1, .cdxml, .mof, and .js
# Requires installation of osslsigncode
# Run: brew install osslsigncode -  https://github.com/mtrojnar/osslsigncode/
# Runs osslsigncode verify -in <path to download>. 
# When building recipes, run the above to retrieve Signer info

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


class OsslsigncodeVerifier(Processor):
    description = "Validates the signature of an installer, script or executable using opensslsigncode"
    input_variables = {
        "pathname": {
            "required": False,
            "description": "Path to the downloaded file to be verified, defaults to %pathname%",
        },
        "osslsigncode_path": {
            "required": False,
            "description": "Path to the osslsigncode binary, defaults to /opt/homebrew/bin/osslsigncode",
        },
        "signer_string": {
            "required": True,
            "description": "string to match to Signer 0 subject information (Do not include 'Subject: ')",
        },
        
    }
    output_variables = { 
       "verified": {
          "description": (
              "True if signer_regex matches the Signer 0 subject and"
              "Signature CRL verification and Signature verification are both ok"
              "Otherwise, False"
          )
      }
    }

    __doc__ = description

    def main(self):
        SignerPrefix = "Signer's certificate:\n\t-+\n\tSigner #0:\n\t\tSubject: "
        # Set default path to msiinfo
        if 'arm' in platform.processor():
            osslsigncode_default_path = os.path.abspath("/opt/homebrew/bin/osslsigncode")
        else:
            osslsigncode_default_path = os.path.abspath("/usr/local/bin/osslsigncode")

        # Set osslsigncode variable to input variable or default path
        osslsigncode = self.env.get('osslsigncode_path', osslsigncode_default_path)

        # Set file_path from input
        file_path = self.env.get('pathname')
        verbosity = self.env.get('verbose', 0)

        if subprocess.call(["type", osslsigncode], stdout=subprocess.PIPE, stderr=subprocess.PIPE) != 0:
            self.output("msiinfo executable not found at %s" % osslsigncode)
            raise ProcessorError(
                f"OsslsigncodeVerifier: osslsigncode executable not found. Need to install using `brew install opensslsigncode`"
            )
            sys.exit(1)

        if not os.path.isfile(file_path):
            self.output("Downloaded file path not found: %s" % file_path)
            sys.exit(1)

        self.output("Evaluating: %s" % file_path)
        signature = "Signature verification: ok"
        signatureCRL = "Signature CRL verification: ok"
        signer0Regex = re.compile(SignerPrefix + self.env.get('signer_string'))
        
        if not file_path:
            self.output("file to verify not found")
            sys.exit(1)
        cmd = [osslsigncode, 'verify -in', file_path]
        # self.output(" ".join(cmd))
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        (stdout, stderr) = proc.communicate()

        read_osslsigncode_response = stdout.decode()

        regex_match = re.search(signature, read_osslsigncode_response)
        if regex_match != signature:
            # Signature failed, exit
            verified = False
            self.output("Failed to Verify Signature")
        
        regex_match = re.search(signatureCRL, read_osslsigncode_response)
        if regex_match != signatureCRL:
            # Failed Signature CRL, check signer
            verified = False
            self.output("Failed to Verify Signature CRL")
        
        regex_match = re.search(signer0Regex, read_osslsigncode_response)
        
        if regex_match != self.env.get('signer_string'):
            # Signer Failed, exit
            verified = False
            self.output("Failed to verify Signer #0")
        else:
            verified = True
            self.output("Signature Verified")
        
        if verified == False:
            self.output(read_osslsigncode_response)

        self.output_variables = {}
        self.output_variables['verified'] = verified
        

if __name__ == '__main__':
    processor = OsslsigncodeVerifier()
    processor.execute_shell()
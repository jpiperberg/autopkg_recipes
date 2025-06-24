#!/usr/local/autopkg/python
# -*- coding: utf-8 -*-
#
# Copyright 2016 Nathan Felton (n8felton)
# Modified by Jamie Piperberg (jpiperberg)
# method used takes checksum, not file
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Calculate a message-digest fingerprint (checksum) for a file"""

import hashlib

from autopkglib import Processor, ProcessorError

__all__ = ["MD5Checksum"]


class ValidateMD5Checksum(Processor):
    """Calculate a message-digest fingerprint (checksum) for a file"""
    description = __doc__
    input_variables = {
        "pathname": {
            "required": True,
            "description": "Path of the file to calculate MD5 checksum on."
        },
        "md5checksumfile": {
            "required": False,
            "description": "A MD5 checksum file to verify pathname."
        },
    }
    output_variables = {
        "md5checksum": {
            "description": "MD5 checksum calculated from pathname."
        },
    }

    def md5(self, file_name):
        md5 = hashlib.md5(open(file_name, 'rb').read())
        return md5.hexdigest()

    def main(self):
        md5checksum = self.md5(self.env["pathname"])
        self.output("{md5checksum}".format(md5checksum=md5checksum), 1)
        verifiedMD5Checksum = open(self.env.get('md5checksumfile')).read()
        self.output("{verifiedMD5Checksum}".format(verifiedMD5Checksum=verifiedMD5Checksum, 1)
        if verifiedMD5Checksum:
            if not verifiedMD5Checksum == md5checksum:
                raise ProcessorError("MD5 Checksum verification failed.")
            else:
                self.output("MD5 Checksum Matches", 1)
        self.env["md5checksum"] = md5checksum

if __name__ == "__main__":
    PROCESSOR = MD5Checksum()
    PROCESSOR.execute_shell()

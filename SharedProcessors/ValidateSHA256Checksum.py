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
"""Calculate a sha256 fingerprint (checksum) for a file"""

import hashlib

from autopkglib import Processor, ProcessorError

__all__ = ["ValidateSHA256Checksum"]


class ValidateSHA256Checksum(Processor):
    """Calculate a sha256 fingerprint (checksum) for a file"""
    description = __doc__
    input_variables = {
        "pathname": {
            "required": True,
            "description": "Path of the file to calculate SHA256 checksum on."
        },
        "sha256_string": {
            "required": False,
            "description": "A sha256 string file to verify pathname."
        },
    }
    output_variables = {
        "sha256_checksum": {
            "description": "sha256 checksum calculated from pathname."
        },
    }

    def sha256(self, file_name):
        sha256 = hashlib.sha256(open(file_name, 'rb').read())
        return sha256.hexdigest()

    def main(self):
        sha256_checksum = self.sha256(self.env["pathname"])
        self.output("{sha256_checksum}".format(sha256_checksum=sha256_checksum), 1)
        verifiedSHA256Checksum = self.env.get('sha256_string')
        if verifiedSHA256Checksum:
            if not verifiedSHA256Checksum == sha256_checksum:
                raise ProcessorError("SHA256 Checksum verification failed.")
            else:
                self.output("SHA256 Checksum Matches", 1)
        self.env["sha256_checksum"] = sha256_checksum

if __name__ == "__main__":
    PROCESSOR = ValidateSHA256Checksum()
    PROCESSOR.execute_shell()

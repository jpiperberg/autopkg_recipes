#!/usr/local/autopkg/python
#
# Copyright 2013 Shea Craig
# Mostly just reworked code from Per Olofsson/AppDmgVersioner.py and
# Greg Neagle/Versioner.py
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
# Modifed by jpiperberg 2026 to read text files (ASCII, UTF-8 or UTF-16)
"""See docstring for FileTextReader class"""

import glob
import os.path

from autopkglib import ProcessorError

__all__ = ["FileTextReader"]


class FileTextReader(Processor):
    """Loads file text into a variable to be passed to another processor"""

    description = __doc__
    lifecycle = {"introduced": "0.2.5"}
    input_variables = {
        "file_path": {
            "required": True,
            "description": (
                "Path to a file to be read. It will read the entire file without interpretation"
            ),
        },
    }
    output_variables = {
        "file_text": {
            "description": (
                "string text of the provided file"
            )
        }
    }

    def main(self) -> None:

        # Many types of paths are accepted. Figure out which kind we have.
        path = os.path.normpath(self.env["file_path"])

        try:
            # check whether this is at least a valid path
            if not os.path.exists(path):
                raise ProcessorError(f"Path '{path}' doesn't exist!")
            
            # Try to read the file
            self.output(f"Reading: {path}")
            try:
                with open(path, "rb") as f:
                    file_text = f.read()
            except Exception as err:
                raise ProcessorError(err)

            # Copy string into output variable
            if type(file_text) == bytes:
                try:
                    self.env["file_text"] = file_text.decode('UTF-8')
                except:
                    self.env["file_text"] = file_text.decode('UTF-16')
            else:
                self.env["file_text"] = file_text
        except:
            raise ProcessorError(f"Error reading file at '{path}'")


if __name__ == "__main__":
    PROCESSOR = FileTextReader()
    PROCESSOR.execute_shell()
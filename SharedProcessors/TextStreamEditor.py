#!/usr/local/autopkg/python
#
# Refactoring 2018 Michal Moravec
# Copyright 2015 Greg Neagle
# Based on URLTextSearcher.py, Copyright 2014 Jesse Peterson
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
# Allow editing of stream with sed
"""See docstring for TextStreamEditor class"""

import re
import subprocess
from autopkglib import ProcessorError

MATCH_MESSAGE = "Found matching text"
NO_MATCH_MESSAGE = "No match found on text"

__all__ = ["TextStreamEditor"]


class TextStreamEditor(Processor):
    """Takes a source string and modifies it with the sed commands"""

    description = __doc__
    lifecycle = {"introduced": "2.7.9"}
    input_variables = {
        "source_string": {
                    "required": True,
                    "description": "text to apply sed expression to.",
        },
        "sed_expression": {
            "required": True,
            "description": "Sed expression to apply to source_string ( do not include 'sed')",
        },
        "result_output_var_name": {
            "required": False,
            "description": (
                "The name of the output variable that is returned "
                "by the edited text. If not specified then a default of "
                '"edited_string" will be used.'
            ),
            "default": "edited_string",
        },
        "request_headers": {
            "required": False,
            "description": (
                "Optional dictionary of headers to include with "
                "the download request."
            ),
        },
        "curl_opts": {
            "required": False,
            "description": (
                "Optional array of curl options to include with "
                "the download request."
            ),
        },
        "re_flags": {
            "required": False,
            "description": (
                "Optional array of strings of Python regular "
                "expression flags. E.g. IGNORECASE."
            ),
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

    def main(self) -> None:
        output_var_name = self.env["result_output_var_name"]
        source_string = self.env["source_string"]
        sed_expression = self.env["sed_expression"]
        # assemble command
        command = r"echo {0} |  sed '{1}'".format(source_string, sed_expression)
        self.output("Preparing to execute command: {0}".format(command))
        edited_string = subprocess.run(command, capture_output=True, shell=True).stdout.decode().strip()
        self.output("Edited String is: {0}".format(edited_string))
       
        self.env[output_var_name] = edited_string


if __name__ == "__main__":
    PROCESSOR = TextStreamEditor()
    PROCESSOR.execute_shell()
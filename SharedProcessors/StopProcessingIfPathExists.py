#!/usr/local/autopkg/python
#
# Copyright 2013 Greg Neagle
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
"""See docstring for StopProcessingIf class"""

from autopkglib import Processor, ProcessorError, log_err, StopProcessingIf
import os

try:
    from Foundation import NSPredicate
except ImportError:
    log_err("WARNING: Failed 'from Foundation import NSPredicate' in " + __name__)

__all__ = ["StopProcessingIfPathExists"]


class StopProcessingIfPathExists(StopProcessingIf):
    """Sets a variable to tell AutoPackager to stop processing a recipe if a
    file/folder path exists."""

    description = __doc__
    lifecycle = {"introduced": "2.7.6}
    input_variables = {
        "path_to_test": {
            "required": True,
            "description": (
                "POSIX style path to file or folder to test if it exists"
            ),
        }
    }
    output_variables = {
        "stop_processing_recipe": {
            "description": "Boolean. Should we stop processing the recipe?"
        }
    }

    def path_exists(self, path_to_test):
        """Tests file/folder path"""
        if os.path.islink(path_to_test) or os.path.isfile(path_to_test) or os.path.isdir(path_to_test):
					path_exists = True
				else:
          path_exists = False
        return result

    def main(self) -> None:
        self.env["stop_processing_recipe"] = self.path_exists(
            self.env["path_to_test"]
        )


if __name__ == "__main__":
    PROCESSOR = StopProcessingIf()
    PROCESSOR.execute_shell()
#!/usr/local/autopkg/python
#
# Copyright 2011 Per Olofsson
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
# Merging some functionality of autopkglib FileCreator and PkgRootCreator to 
# allow folder creation based on variable expansion
"""Processor that creates a folder"""

import os
import shutil

from autopkglib import FileCreator
from autopkglib import ProcessorError

__all__ = ["FolderCreator"]


class FolderCreator(FileCreator):
	"""Create a folder."""

	description = __doc__
	input_variables = {
		"folder_path": {
			"required": True, 
			"description": "Path to a folder to create."
		},
		"overwrite": {
			"required": False, 
			"default": False,
			"description": 
				"Overwrite if a folder with the same name exists. "
				"Defaults to False"
			},
		"ignore_existing": {
			"required": False, 
			"default": False,
			"description": 
				"Continue without error if the folder exists. "
				"Will set permissions on folder if specified. "
				"Defaults to False"
			},
		"folder_mode": {
			"required": False,
			"description": 
				"String. Numeric mode for folder in octal format."
				"Default is root:admin 01775",
		},
	}
	output_variables = {}

	def Create(self, folder_path, overwrite, ignore_existing):
		folder_exists = False
		self.output("creating folder_path")
		if overwrite:
		# Delete folder if it exists.
			self.output("will overwrite if folder exists")
			try:
				if os.path.islink(folder_path) or os.path.isfile(folder_path):
					os.unlink(folder_path)
				elif os.path.isdir(folder_path):
					shutil.rmtree(folder_path)
			except OSError as err:
				raise ProcessorError(f"Can't remove {folder_path}: {err.strerror}")
		else:
			self.output("will not overwrite if folder exists")
			if os.path.islink(folder_path) or os.path.isfile(folder_path) or os.path.isdir(folder_path):
				if ignore_existing:
					folder_exists = True
				else:
					raise ProcessorError(f"{folder_path} exists. Exiting:")
		if not folder_exists:
			# Create folder_path. autopkghelper sets it to root:admin 01775.
			self.output("creating folder folder_path")
			try:
				os.makedirs(folder_path)
				
				self.output(f"Created {folder_path}")
			except OSError as err:
				raise ProcessorError(f"Can't create {folder_path}: {err.strerror}")


	def main(self):
		self.Create(self.env['folder_path'], self.env['overwrite'], self.env['ignore_existing']) 
		if "folder_mode" in self.env:
			try:
				os.chmod(self.env["folder_path"], int(self.env["folder_mode"], 8))
				self.output(f"updating permissions")
			except:
				raise ProcessorError(
					f"Can't set permissions of {self.env['folder_path']}"   		
					f" to {self.env['folder_mode']}")
		else:
			self.output(f"permissions left as default")
		 
if __name__ == "__main__":
	PROCESSOR = FolderCreator()
	PROCESSOR.execute_shell()
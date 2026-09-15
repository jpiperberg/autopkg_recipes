#!/usr/bin/env python3
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
#
# Based on CreateISOProvider by Rusty Myers
# https://github.com/autopkg/rustymyers-recipes/blob/master/SharedProcessors/createISOProvider.py
# and wimcreate.py by DanPSUK
# https://github.com/DanPSUK/python_script/blob/main/wimcreate.py

# Use with com.github.jpiperberg.SharedProcessors/createWIMProvider as processor name
# Requires wimlib
# https://wimlib.net/

import os
import glob
from autopkglib import ProcessorError
import subprocess


__all__ = ["createWIMProvider"]

class createWIMProvider(DmgMounter):
  description = ("Creates an WIM from source_path")
  input_variables = {
    "source_path": {
      "required": True,
      "description": ("Path to a file or folder. "
                      "Can point to a globbed path inside a .dmg which will "
                      "be mounted.")
    },
    "destination_path": {
      "required": True,
      "description": ("Destination Path for WIM. Should be a folder. ")
    },
    "wim_name": {
      "required": False,
      "description": ("Name for the wim (without .wim), defaults to basename of source_path"),
      "default": ""
    },
    "overwrite": {
      "required": False,
      "description": ("Defaults to True. Boolean to overwrite WIM if it already exists."),
      "default": True
    },
    "validate": {
       "required": False,
       "description": ("Defaults to False. Boolean to determine whether to test the wim. Increases space usage and time requirements"),
       "default": False
    },
    "volume_name": {
      "required": False,
      "description": ("Defaults to first 8 of destination_path basename. Limited to 8 characters"),
      "default": "" # set in main
    },
    "volume_descripton": {
      "required": False,
      "description": ("Defaults to wim_name"),
      "default": "" # set in main
    },
    "compression_type": {
       "required": False,
       "description": ("compression_type may be \"none\", \"XPRESS\" (alias: \"fast\"), \"LZX\" (alias: \"maximum\"), or \"LZMS\" (alias: \"recovery\"). Defaults to \"fast\""),
       "default": "fast"
    }
  }
  output_variables = {
    "wim_path": {
      "description": "Path to created wim.",
    }
  }

  def validate_wim(self, source_path, target_wim):
    """ Validates created wim file """
    wim_test = f"{os.getcwd()}\\testmount"
    if not os.path.exists(wim_test):
        os.makedirs(wim_test)

    result = subprocess.run(
      [
        "wimapply",
        f"{target_wim}",
        f"{wim_test}",
      ],
        capture_output=True,
        text=True
    )
    self.output(f"Expanded {target_wim}: {result.stdout}")
    # compare folders
    result = subprocess.run(
      [
        "diff",
       "-rq",
       f"{wim_test}",
       f"{source_path}"
       ], 
       capture_output=True, text=True
    )
    if result.returncode != 0:
      raise ProcessorError(
        [
          "Verification failed:",
          "File mismatches:\n",
          result.stdout,
        ]
      )
    os.remove(wim_test)

  def createWIM(self, source_path, destination_wim, volume_name, volume_descripton, compression_type, overwrite):
    """
    Creates WIM from source_path
    """
    if os.path.exists(f"{source_path}/.DS_Store"):
      os.remove(f"{source_path}/.DS_Store")

    destination_path = self.env.get("destination_path")
    if not os.path.exists(destination_path):
      os.makedirs(destination_path)
    if os.path.exists(f"{destination_path}/.DS_Store"):
      os.remove(f"{destination_path}/.DS_Store")
    if os.path.exists(destination_wim):
      self.output("Destination WIM exists")
      if os.path.isfile(destination_wim) and overwrite:
        self.output("Removing old WIM")
        os.remove(destination_wim)
      elif os.path.isfile(destination_wim) and (not overwrite):
        raise ProcessorError(
          f"Error: {destination_wim} exists and overwrite is False"
        )
      else:
        raise ProcessorError(
          f"Error: destination_wim '{destination_wim}' is a folder!.")
    else:
      self.output("No old wim")

    if len(volume_name) > 0:
        VOLUME_NAME = volume_name[:8]
    else:
        VOLUME_NAME = os.path.basename(source_path)[:8]	
    self.output("VOLUME_NAME: {0}".format(VOLUME_NAME))
    result = subprocess.run(
      [
        "wimcapture",
        f"{source_path}",
        f"{destination_wim}.wim",
        f"{VOLUME_NAME}",
        f"{volume_descripton}",
        "--check",
        f"--compress={compression_type}",
      ],
      capture_output=True,
      text=True
    )
    self.output(f"Wimcapture result: {result.stdout}")
    result = subprocess.run(
      [
        "wiminfo",
        f"{destination_wim}.wim",
      ],
      capture_output=True,
      text=True
    )
    self.output(f"Wiminfo result: {result.stdout}")

def main(self):
  source_path = self.env["source_path"]
  RECIPE_CACHE_DIR = self.env.get("RECIPE_CACHE_DIR")
  version = self.env.get("version")
  extension = "wim"
  volume_name = self.env["volume_name"]
  volume_descripton = self.env["volume_descripton"]
  validate = self.env["validate"]
  wim_name = self.env["wim_name"]

  if not os.path.exists(source_path):
    raise ProcessorError(f"Source path{source_path} does not exist")

  # Check for presence of wimlib
  result = subprocess.run(
    [
      "which",
      "wimcapture",
    ],
    capture_output=True,
    text=True
  )
  if result.stdout.find("not found") < 0:
    raise ProcessorError(f"wimlib not installed, please run 'brew install wimlib'")

  if len(wim_name) == 0:
    # Set name from Source Path
    name = "{0}-{1}".format(os.path.basename(source_path), version)
    self.output("name: {0}".format(name))
  else:
    name = wim_name
    self.output("name: {0}".format(name))
  # Default destination_path
  if len(volume_name) == 0:
    volume_name = os.path.basename(source_path)[:8]
      
  if len(volume_descripton) == 0:
    volume_descripton = wim_name
  destination_name = "{0}.{1}".format(name, extension)
  destination_wim = "{0}/{1}".format(RECIPE_CACHE_DIR, destination_name)
  if self.env.get("destination_path"):
    destination_path = self.env.get("destination_path")
    self.output("Using provided destination_path value")
    destination_wim = "{0}{1}.{2}".format(destination_path, destination_name, extension)
  
  if self.env.get("overwrite"):
    overwrite = self.env.get("overwrite")
  else:
    overwrite = True

  try:
    matches = glob.glob(source_path, recursive=True)
    if len(matches) == 0:
      raise ProcessorError(
          f"Error processing path '{source_path}' with glob."
      )
    matched_source_path = matches[0]
    if len(matches) > 1:
      self.output(
        f"WARNING: Multiple paths match 'source_path' glob '{source_path}':"
      )
      for match in matches:
        self.output(f"  - {match}")
    if [c for c in "*?[]!" if c in source_path]:
      self.output(
        f"Using path '{matched_source_path}' matched from "
        f"globbed '{source_path}'."
      )
    self.output(
      f"Using source path: '{source_path}'\n"
      f"WIM path:  '{destination_wim}'\n"
      f"Overwrite: '{overwrite}'"
    )
    # Create WIM and set path
    self.createWIM(
      source_path,
      destination_wim,
      volume_name,
      volume_descripton,
      overwrite)
    self.env["wim_path"] = destination_wim
  except:
    raise ProcessorError(f"Error creating wim from {source_path} to {destination_wim}.wim")

  if self.env.get["validate"]:
    self.validate_wims(self,source_path, f"{destination_wim}.wim")

if __name__ == '__main__':
    processor = createWIMProvider()
    processor.execute_shell()

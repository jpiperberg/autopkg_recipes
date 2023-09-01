#!/usr/local/autopkg/python
# 
# Embraced and extended 2023 Jamie Piperberg
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
"""See docstring for URLTextSearcher class"""

import re, urllib.parse

from autopkglib import ProcessorError
from autopkglib.URLGetter import URLGetter
from autopkglib.URLTextSearcher import URLTextSearcher

MATCH_MESSAGE = "Found matching text"
NO_MATCH_MESSAGE = "No match found on URL"
encoded_search_terms = ""

__all__ = ["GetCVEList"]

class GetCVEList(URLTextSearcher):
    """Performs a search of mitre.org database and performs a regular expression match
    on the text returned based on application name and version (version should be the version prior to the version being deployed). Returns all results by default, separated by a delimiter (default is comma).  

    Requires version 1.4."""
    description = "Returns a list of CVEs based on application_name and application_version search terms"
    input_variables = {
        "results_delimiter":{
            "description": {"String to separate results in case of multiple matches.  Defaults to ','."},
            "required": False,
            "default": ",",
        },
        "application_name": {
            "desription": {
                "array of search criteria.  Suggest vendor & app name."
                "By default when making the request, they will be separated by '+'"
                "Any special characters will be replaced with their %code equivalents"
            },
            "required": True,       
        },
        "application_version": {
            "desription": {
                "Version prior to version being patched."
                "If only current version can be patched, pass \"True\" to"
                "calculate_prior_version"
            },
            "required": True,       
        },
        "guess_prior_version":{
            "description": {
                "Attempts to guess prior version of application"
                "will decrement the last component of the version passed"
                "(and priorcomponent(s) if last component is 0"
            },
            "required:": False,    
            "default":  False,  
        },
    }
    output_variables = {
        "cve_list": {
            "description": (
                "First matched sub-pattern from input found on the fetched "
                "URL. Note the actual name of variable depends on the input "
                'variable "result_output_var_name" or is assigned a default of '
                '"match."'
            )
        }
    }

    description = __doc__
    
    def determine_prior_version(self):
        """attempts to decrement last section of version passed"""
        search_version = self.env.get("application_version")
        reversed_version = search_version.reverse()
        minor_version = (minor_version.split('.')).reverse()
        if int(minor_version) == 0:
            prior_minor_version = str(9)
            
        else:
            prior_minor_version = str(minor_version)
        
    def prepare_search_terms(self):
        """Replace spaces with search delimiter and special characters with %codes"""
        self.output('Search terms: %s' % self.env["application_name"])
        self.env.encoded_search_terms = urllib.parse.urlencode(self.env.get('application_name'))
        self.output('Encoded search terms: %s' % self.env["encoded_search_terms"])
            
    def prepare_curl_cmd(self):
        """Assemble curl command and return it."""
        curl_cmd = super().prepare_curl_cmd()
        if self.env.get(guess_prior_version):
            search_version = determine_prior_version()
        else:
            search_version = self.env.get("application_version")
        # add search terms to url
        
        curl_cmd.append(self.env["url"])
        curl_cmd.append(self.env["encoded_search_terms"])
        curl_cmd.append(self.env[])
        self.output('search url: %s' % curl_cmd)
        return curl_cmd

    def main(self):
        output_var_name = "cve_list"
        self.env("url") = "https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword="

        # Prepare curl command
        curl_cmd = self.prepare_curl_cmd()

        # Execute curl command and search in content
        content = super().download_with_curl(curl_cmd)
        groupmatch, groupdict = super().re_search(content)

        # favor a named group over a normal group match
        if output_var_name not in groupdict.keys():
            groupdict[output_var_name] = groupmatch

        self.output_variables = {}
        for key in groupdict.keys():
            self.env[key] = groupdict[key]
            self.output(f"{MATCH_MESSAGE} ({key}): {self.env[key]}")
            self.output_variables[key] = {
                "description": "Matched regular expression group"
            }


if __name__ == "__main__":
    PROCESSOR = GetCVEList()
    PROCESSOR.execute_shell()
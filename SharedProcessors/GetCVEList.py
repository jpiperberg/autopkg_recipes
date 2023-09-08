#!/usr/local/autopkg/python

# Uses the mitre.org database to retrieve CVEs for passed
# Application Name and version
# Attempts to decrement version if requested. 

"""

This processor extends the autopkglib.URLTextSearcherArray processor
by JGStew to provide easier to use functionality to retrieve CVEs

"""

import re, urllib.parse

from autopkglib import ProcessorError  
from autopkglib.URLTextSearcher import URLTextSearcher  

# import sys

# sys.path.append("/Library/AutoPkg")


MATCH_MESSAGE = "Found matching text"
NO_MATCH_MESSAGE = "No match found on URL"
encoded_search_terms = ""

__all__ = ["GetCVEList"]


class GetCVEList(URLTextSearcher):
    """Downloads a URL using curl and performs a regular expression match
    on the text. Returns an Array of matches instead of first match.
    Requires version 1.4."""

    input_variables = {
        "re_pattern": {
            "description": "Regular expression (Python) to match against page.",
            "required": False, 
            "default": "(?<=name=)CVE-\d*-\d*(?=\")"    
        },
        "url": {
            "description": "URL to download", 
            "required": False, 
            "default": "https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword="    
        },
        "result_output_var_name": {
            "description": (
                "The name of the output variable that is returned "
                "by the match. If not specified then a default of "
                '"CVEList" will be used.'
            ),
            "required": False,
            "default": "CVEList",
        },
        "request_headers": {
            "description": (
                "Optional dictionary of headers to include with "
                "the download request."
            ),
            "required": False,
        },
        "curl_opts": {
            "description": (
                "Optional array of curl options to include with "
                "the download request."
            ),
            "required": False,
        },
        "re_flags": {
            "description": (
                "Optional array of strings of Python regular "
                "expression flags. E.g. IGNORECASE."
            ),
            "required": False,
        },
        "results_delimiter": {
            "description": (
                "String to separate results in case of multiple matches."
                "Defaults to ','."
            ),
            "required": False,
            "default": ",",
        },
        "application_name": {
            "desription": (
                "array of search criteria.  Suggest vendor & app name."
                "By default when making the request, they will be separated by '+'"
                "Any special characters will be replaced with their %code equivalents"
            ),
            "required": True,       
        },
        "application_version": {
            "desription": (
                "Version prior to version being patched."
                "If only current version can be patched, pass \"True\" to"
                "calculate_prior_version"
            ),
            "required": True,       
        },
        "guess_prior_version": {
            "desription": (
                "Attempts to guess prior version of application"
                "will decrement the last component of the version passed"
                "(and priorcomponent(s) if last component is 0"
            ),
            "required": False,       
            "default": False, 
        },
        "full_results": {
            "description": (
                "boolean flag - if true return all results" "Default: False"
            ),
            "required": False,
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

    description = __doc__

    def re_search(self, content):
        """Search for re_pattern in content"""

        re_pattern = re.compile(self.env["re_pattern"], flags=self.prepare_re_flags())
        match_array = re_pattern.findall(content)

        if not match_array:
            raise ProcessorError(f"{NO_MATCH_MESSAGE}: {self.env['url']}")

        # return array of matches
        return match_array
        
    def determine_prior_version(self):
        """attempts to decrement last section of version passed"""
        search_version = self.env["application_version"]
        version_list = search_version.split('.')
        component_count = len(version_list)
        build_version = int(version_list[(component_count - 1)])
         
        if build_version == 0:
            version_list[component_count - 1] = "9"
            i = component_count - 2
            while i >= 0:
                if int(version_list[i]) == 0:
                    version_list[i] = 9
                    i -= 1
                else:
                    i = -1
            
        else:
            version_list[(component_count - 1)] = (build_version - 1)
#             self.output('version_list %s' % str(version_list))
        # reassemble version
        i = 0
        reassembled_version = ""
        while i < (component_count - 1):
            reassembled_version += str(version_list[i]) + "."
            i += 1
            
        reassembled_version += str(version_list[component_count - 1])
#         self.output('reassembled_version %s' % str(reassembled_version))
        return reassembled_version
        
    def prepare_search_terms(self):
        """Replace spaces with search delimiter and special characters with %codes"""
#         self.output('Search terms: %s' % self.env["application_name"])
        search_terms = self.env["application_name"]
        search_count = len(search_terms)
        i = 0
        self.encoded_search_terms = []
        while i < search_count:
            self.encoded_search_terms.append(urllib.parse.quote_plus(str(search_terms[i]), safe='', encoding=None, errors=None)) 
#             self.output('Encoded search terms: %s' % self.encoded_search_terms[i])
            i += 1
            self.output('i = %s' % str(i))
                        
    def prepare_curl_cmd(self):
        """Assemble curl command and return it."""
        
        self.prepare_search_terms()
        if self.env.get("guess_prior_version"):
            search_version = self.determine_prior_version()
        else:
            search_version = self.env("application_version")

        search_count = len(self.encoded_search_terms)
        i = 0
        while i < search_count:
            self.env["url"] += self.encoded_search_terms[i]
            self.env["url"] += "+"
            i += 1
        self.env["url"] += search_version
#         self.output('search url: %s' % self.env.get("url"))
        curl_cmd = super().prepare_curl_cmd()

        return curl_cmd


    def main(self):
        """execution starts here"""

        output_var_name = "cve_list"
        full_results = self.env.get("full_results", False)

        # Prepare curl command
        curl_cmd = self.prepare_curl_cmd()

        # Execute curl command and search in content
        content = self.download_with_curl(curl_cmd)

        self.output(f"URL Content:\n{content}", 5)

        match_array = self.re_search(content)

        self.output(match_array, 2)

        if not full_results:
            match_array = list(set(match_array))

        self.env[output_var_name] = match_array


if __name__ == "__main__":
    PROCESSOR = GetCVEList()
    PROCESSOR.execute_shell()

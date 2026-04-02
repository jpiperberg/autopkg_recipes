#!/usr/local/autopkg/python
# Copyright 2026 Jamie Piperberg
# Based on URL Downloader
# Refactoring 2018 Michal Moravec
# Copyright 2015 Greg Neagle
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
"""See docstring for URLDownloader class"""

import os.path
import platform
import tempfile
import sys
import time
import requests
from jwt import (
    JWT,
    jwk_from_dict,
    jwk_from_pem,
)


from autopkglib import BUNDLE_ID, ProcessorError, xattr, URLDownloader

__all__ = ["GitHubAuthenticatedDownload"]


class GitHubAuthenticatedDownload(URLDownloader):
    """Downloads a URL from an authenticated GitHub Repo the specified download_dir using curl."""

    description = __doc__
    lifecycle = {"introduced": "0.1.0"}
    input_variables = {
        "url": {"required": True, "description": "The URL to download."},
        "client_ID": {
            "required": True,
            "description": (
                "Client ID to use for authenticated download to private GitHub repo. "
                "https://docs.github.com/en/rest/repos/contents"
                "https://docs.github.com/en/rest/releases/assets"
                "Or use GitHubReleasesInfoProvider"
                "https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-json-web-token-jwt-for-a-github-app "
            ),
        },
         "installation_ID": {
            "required": True,
            "description": (
                "Installation ID to use for authenticated download to private GitHub repo. "
                "https://docs.github.com/en/rest/apps/apps?apiVersion=2026-03-10#create-an-installation-access-token-for-an-app"
            ),
        },
        "PEM_file_path": {
            "required": True,
            "description": (
                "Used to generate the JWT"
                "https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-a-json-web-token-jwt-for-a-github-app "  
            ),
        },
        "request_headers": {
            "required": False,
            "description": (
                "Optional dictionary of headers to include with the download request."
            ),
        },
        "curl_opts": {
            "required": False,
            "description": (
                "Optional array of options to include with the download request."
            ),
        },
        "download_dir": {
            "required": False,
            "description": (
                "The directory where the file will be downloaded to. Defaults "
                "to RECIPE_CACHE_DIR/downloads."
            ),
        },
        "filename": {
            "required": False,
            "description": "Filename to override the URL's tail.",
        },
        "prefetch_filename": {
            "required": False,
            "description": (
                "If True, URLDownloader attempts to determine filename from HTTP "
                "headers downloaded before the file itself. 'prefetch_filename' "
                "overrides 'filename' option. Filename is determined from the first "
                "available source of information in this order:\n"
                "\t1. Content-Disposition header\n"
                "\t2. Location header\n"
                "\t3. 'filename' option (if set)\n"
                "\t4. last part of 'url'.  \n"
                "'prefetch_filename' is useful for URLs with redirects."
            ),
            "default": False,
        },
        "CHECK_FILESIZE_ONLY": {
            "required": False,
            "description": (
                "If True, a server's ETag and Last-Modified "
                "headers will not be checked to verify whether "
                "a download is newer than a cached item, and only "
                "Content-Length (filesize) will be used. This "
                "is useful for cases where a download always "
                "redirects to different mirrors, which could "
                "cause items to be needlessly re-downloaded. "
                "Defaults to False."
            ),
            "default": False,
        },
        "PKG": {
            "required": False,
            "description": (
                "Local path to the pkg/dmg we'd otherwise download. "
                "If provided, the download is skipped and we just use "
                "this package or disk image."
            ),
        },

    }
    output_variables = {
        "pathname": {"description": "Path to the downloaded file."},
        "last_modified": {
            "description": "last-modified header for the downloaded item."
        },
        "etag": {"description": "etag header for the downloaded item."},
        "download_changed": {
            "description": (
                "Boolean indicating if the download has changed since the "
                "last time it was downloaded."
            )
        },
        "url_downloader_summary_result": {
            "description": "Description of interesting results."
        },
    }


    def get_download_token(self) -> str:
        """Use client ID and jwt to request a token"""

        # Get PEM file path
        pem = self.env['PEM_file_path']

        # Get the Client ID
        client_id = self.env['client_ID']

        # Open PEM
        with open(pem, 'rb') as pem_file:
            signing_key = jwk_from_pem(pem_file.read())

        payload = {
            # Issued at time
            'iat': int(time.time()),
            # JWT expiration time (10 minutes maximum)
            'exp': int(time.time()) + 600,
            
            # GitHub App's client ID
            'iss': client_id
        }
        jwt = JWT()
        # Create JWT
        encoded_jwt = jwt.encode(payload, signing_key, alg='RS256')
        self.output("jwt encoded as: {0}".format(encoded_jwt))
        headers = {
            'Accept': 'application/vnd.github+json',
            'Authorization': 'Bearer {0}'.format(encoded_jwt),
            'X-GitHub-Api-Version': '2026-03-10',
        }

        result = requests.post('https://api.github.com/app/installations/119192899/access_tokens', headers=headers)
        
        error = result.raise_for_status()
        if error:  
            raise ProcessorError(f"curl failure: {error}")
        result_json = result.json()
        token = result_json["token"]
        self.output("token expiration: {0}".format(result_json['expires_at']))
        
        return token

    def build_authenticated_url(self, curl_cmd) -> str:
        """Using the token, combine the url and the token to built an authenticated url"""
        token = self.get_download_token()
        self.output(token)
        headers = {
            "Accept": "application/vnd.github.raw+json",
            "Authorization": "Bearer {0}".format(token),
            "X-GitHub-Api-Version": "2026-03-10"
        }
        self.add_curl_headers(curl_cmd, headers)


    def main(self) -> None:
        # Clear and initialize data structures
        self.clear_vars()

        # Ensure existence of necessary files, directories and paths
        filename = self.get_filename()
        if filename is None:
            return
        download_dir = self.get_download_dir()
        self.env["pathname"] = os.path.join(download_dir, filename)
        pathname_temporary = self.create_temp_file(download_dir)

        # Prepare download curl command
        curl_cmd = self.prepare_download_curl_cmd(pathname_temporary)

        # Add authentication headers
        self.build_authenticated_url(curl_cmd)

        # Execute curl command and parse headers
        raw_headers = self.download_with_curl(curl_cmd)
        header = self.parse_headers(raw_headers)

        if self.download_changed(header):
            self.env["download_changed"] = True
        else:
            # Discard the temp file
            os.remove(pathname_temporary)
            return

        # New resource was downloaded. Move the temporary download file to the pathname
        self.move_temp_file(pathname_temporary)

        # Save last-modified and etag headers to files xattr
        self.store_headers(header)

        # Generate output messages and variables
        self.output(f"Downloaded {self.env['pathname']}")
        self.env["url_downloader_summary_result"] = {
            "summary_text": "The following new items were downloaded:",
            "data": {"download_path": self.env["pathname"]},
        }


if __name__ == "__main__":
    PROCESSOR = GitHubAuthenticatedDownload()
    PROCESSOR.execute_shell()
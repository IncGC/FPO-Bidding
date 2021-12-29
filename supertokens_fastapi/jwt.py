"""
Copyright (c) 2020, VRAI Labs and/or its affiliates. All rights reserved.

This software is licensed under the Apache License, Version 2.0 (the
"License") as published by the Apache Software Foundation.

You may not use this file except in compliance with the License. You may
obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations
under the License.
"""

from supertokens_fastapi.utils import (
    utf_base64decode,
    utf_base64encode
)
from json import (
    loads,
    dumps
)
from Crypto.PublicKey import RSA
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
from Crypto.Hash import SHA256
from base64 import b64decode
from textwrap import wrap

_key_start = '-----BEGIN PUBLIC KEY-----\n'
_key_end = '\n-----END PUBLIC KEY-----'

"""
why separators is used in dumps:
- without it's use, output of dumps is: '{"alg": "RS256", "typ": "JWT", "version": "1"}'
- with it's use, output of dumps is: '{"alg":"RS256","typ":"JWT","version":"1"}'

we require the non-spaced version, else the base64 encoding string will end up different than required
"""
_allowed_headers = [utf_base64encode(dumps({
    'alg': 'RS256',
    'typ': 'JWT',
    'version': '2'
}, separators=(',', ':'), sort_keys=True))]


def get_payload(jwt, signing_public_key):
    splitted_input = jwt.split(".")
    if len(splitted_input) != 3:
        raise Exception("invalid jwt")

    header, payload, signature = splitted_input
    if header not in _allowed_headers:
        raise Exception("jwt header mismatch")

    public_key = RSA.import_key(
        _key_start +
        "\n".join(
            wrap(
                signing_public_key,
                width=64)) +
        _key_end)
    verifier = PKCS115_SigScheme(public_key)
    to_verify = SHA256.new((header + "." + payload).encode('utf-8'))
    try:
        verifier.verify(to_verify, b64decode(signature.encode('utf-8')))
    except BaseException:
        raise Exception("jwt verification failed")

    return loads(utf_base64decode(payload))

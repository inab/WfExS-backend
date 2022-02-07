#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright 2020-2022 Barcelona Supercomputing Center (BSC), Spain
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
from __future__ import absolute_import

import functools
import random
import subprocess
from typing import List

DEFAULT_PASSPHRASE_LENGTH = 6

@functools.lru_cache()
def _get_wordlist_tags() -> List[str]:
	"""
	This method learns the available list of wordlists, in order
	to choose one of them randomly
	"""
	import re
	wordlistPat = re.compile(r'\[-w \{([^}]+)\}')
	wordlists_tags = None
	with subprocess.Popen(['pwgen-passphrase', '-h'], encoding='utf-8', stdout=subprocess.PIPE) as p:
		for line in p.stdout:
			matched = wordlistPat.search(line)
			if matched:
				wordlists_tags = matched.group(1).split(',')
	
	return wordlists_tags

def generate_passphrase(passphrase_length:int = DEFAULT_PASSPHRASE_LENGTH) -> str:
	"""
	This method is needed to avoid future legal issues using a GPL-3.0
	library from within an Apache 2.0 licenced code
	"""
	wordlists_tags = _get_wordlist_tags()
	chosen_wordlist = wordlists_tags[random.randrange(len(wordlists_tags))]

	with subprocess.Popen(['pwgen-passphrase', '-w', chosen_wordlist, '-l', str(passphrase_length)], encoding='utf-8', stdout=subprocess.PIPE) as pg:
		for line in pg.stdout:
			return line.rstrip()

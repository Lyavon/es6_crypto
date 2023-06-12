#!/bin/sh

# Copyright 2023 Leonid Ragunovich
#
# This file is part of es6_crypto.
#
# es6_crypto is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
# FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
# more details.
#
# You should have received a copy of the GNU General Public License along with
# this program (see LICENSE file in parent directory). If not, see
# <https://www.gnu.org/licenses/>.

src="$(dirname -- "$(realpath "$(dirname -- "$0")")")/src/*.js"
standard \
  --global crypto \
  --global indexedDB \
  --fix \
  "$src"

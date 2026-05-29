#!/bin/sh
# Install the project's git hooks by pointing git at the tracked .githooks/
# directory. Run once after cloning:
#
#   sh scripts/install-hooks.sh
#
# This is equivalent to running:
#
#   git config core.hooksPath .githooks

set -e

git config core.hooksPath .githooks
echo "Git hooks installed. core.hooksPath set to .githooks/"

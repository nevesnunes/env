#!/usr/bin/env sh

set -eu

php -l *.php
exec php -S localhost:8000

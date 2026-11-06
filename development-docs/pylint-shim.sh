#!/bin/sh

exec pylint --jobs "$(python -V|grep -q PyPy && echo 1 || echo 0)" "$@"


#!/bin/bash

# Build
python setup.py sdist bdist_wheel

# Upload
python -m twine upload dist/*

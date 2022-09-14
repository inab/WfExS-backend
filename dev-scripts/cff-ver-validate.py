#!/usr/bin/env python

import os.path
import argparse
import sys

from cffconvert.cli.create_citation import create_citation
from cffconvert.cli.validate_or_write_output import validate_or_write_output
from distutils.core import run_setup

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="CFF validator and checker")
    ap.add_argument("cfffile", help="The CFF file to validate against ")
    ap.add_argument("packagedir", help="Directory where the setup.py of the package is living", nargs="?", default=None)
    
    args = ap.parse_args()

    if os.path.isfile(args.cfffile):
        packagedir = os.path.dirname(args.cfffile) if args.packagedir is None else args.packagedir
        citation = create_citation(args.cfffile, None)
        validate_or_write_output(outfile=None, outputformat=None, validate_only=True, citation=citation)
        # Now, validate version
        citver = citation._implementation.cffobj['version']
        pkgdist = run_setup(os.path.join(packagedir, "setup.py"), script_args=['check'])
        if pkgdist.metadata.version != citver:
            print(f"Version mismatch: {pkgdist.metadata.version} vs {citver}")
            sys.exit(1)
        else:
            sys.exit(0)
    else:
        print(f"File {args.cfffile} does not exist", file=sys.stderr)
        sys.exit(1)


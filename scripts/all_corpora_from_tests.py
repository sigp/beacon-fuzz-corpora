#! /usr/bin/env python3

""" A simple helper that, given the directory structure in the Eth2 Specs tests,
will generate a directory containing all possible beacon_fuzz corpora.

Fairly basic implementation, just calls corpora_from_tests.py for each type.
Ensure the spec version and spec test versions are the same!

"""

import argparse
import typing
import logging
import sys
import pathlib
import corpora_from_tests


def get_args(
    argv=None, op_names: typing.Optional[typing.Sequence[str]] = None
) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=("Extracts all basic fuzzing corpora from eth2 operation spec tests. "
            "as described in https://github.com/ethereum/eth2.0-specs/tree/dev/specs/test_formats/operations. "
            "NOTE: assumes that the relevant operation tests are in directories with the same name."
            )
    )
    parser.add_argument(
        "--test-root",
        type=pathlib.Path,
        default=".",
        help=("Directory containing relevant ssz files. Defaults to pwd. "
            "This should be the root of spec tests directory ('.../tests/') "
            "or within the config specific section ('.../tests/mainnet') if you only "
            "want to extract 1 type of corpora."),
    )
    parser.add_argument(
        "--out-dir",
        type=pathlib.Path,
        help="Output directory for operation corpora. Defaults to './corpora'",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Replace output directories if they already exist. Generally not required.",
    )
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output.")
    # parser.add_argument("--save_yaml", action="store_true", help="Save YAML files of the test cases.")
    return parser.parse_args(argv)

def main(argv: typing.Optional[typing.Collection[str]] = None) -> int:
    logging.basicConfig(level=logging.INFO)
    args = get_args(argv)
    common_args: typing.List[str] = []
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        common_args.append("--verbose")
    if args.force:
        common_args.append("--force")
    result = 0

    op_names = get_operation_names()

    mainnet_path = find_subdir(args.test_root, "mainnet")
    if mainnet_path:
        logging.info("Finding mainnet tests.")
        operation_path = mainnet_path / "phase0" / "operations"
        if operation_path.exists():
            extract_tests(operation_path, args.out_dir / "mainnet", op_names, common_args)
        else:
            logging.error("Unexpected directory structure: '%r' not present", operation_path)
            result = 1
            # Continue with other config type
    minimal_path = find_subdir(args.test_root, "minimal")
    if minimal_path:
        logging.info("Finding minimal tests.")
        operation_path = minimal_path / "phase0" / "operations"
        if operation_path.exists():
            extract_tests(operation_path, args.out_dir / "minimal", op_names, common_args)
        else:
            logging.error("Unexpected directory structure: '%r' not present", operation_path)
            result = 1
    return result


def extract_tests(operation_root: pathlib.Path, out_dir: pathlib.Path, operation_names: typing.List[str], common_args: typing.List[str]):
    state_path = out_dir / "beaconstate"

    for op in operation_names:
        test_dir = operation_root / op
        if not test_dir.is_dir():
            logging.info("Operation '%s' not found", test_dir)
            continue
        args = ["--search-root", str(test_dir), "--state-out-dir", str(state_path), "--out-dir", str(out_dir / op), op] + common_args
        corpora_from_tests.main(args)


def get_operation_names() -> typing.List[str]:
    """Return list of operation names/directories for which to check.

    Assumes test directories are of the same name.
    """
    return list(corpora_from_tests.load_builtin_registry().keys())


def find_subdir(root: pathlib.Path, subdir_name: str) -> typing.Optional[pathlib.Path]:
    """Recurses through directory contents to find a subdirectory of given name.

    If more than 1 such directory exist, only 1 is returned (unspecified which).
    """
    if not root.is_dir():
        return None
    to_check: typing.List[pathlib.Path] = []
    for child in root.iterdir():
        if child.name == subdir_name and child.is_dir():
            return child
        elif child.is_dir():
            # To make the search breadth-first, we check the contents of the directory before checking subdirectories
            to_check.append(child)
    for d in to_check:
        result = find_subdir(d, subdir_name)
        if result:
            return result
    return None

if __name__ == "__main__":
    sys.exit(main())


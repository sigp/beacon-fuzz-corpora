#! /usr/bin/env python3

"""A helper to create initial corpora from spec test cases.

Fairly inflexible currently, to only make BlockHeaderTestCases

Given some states and some other input, will generate all possible combinations of corpora.

Any new state files found will be appended to the ``--state-out-dir`` with a filename of
increasing number.

The content of existing state files will be compared by hash, so only new states will be appended.
"""

import argparse
import dataclasses
import hashlib
import logging
import pathlib
import shutil
import typing


import ssz
from eth2spec.phase0 import spec
from eth2spec.fuzzing.decoder import translate_typ, translate_value
from eth2spec.utils.ssz.ssz_impl import serialize
from eth2spec.utils.ssz.ssz_typing import uint16, Container, SSZType

# TODO registry? mapping of test/operation names to containers, sedes, test_sedes, file_names?
# Also container constructor, fields need to be kwargs

SV1 = typing.TypeVar("SV1", bound=SSZType)
SV2 = typing.TypeVar("SV2", bound=SSZType)


@dataclasses.dataclass
class OperationRegistryEntry(typing.Generic[SV1]):
    name: str
    operation_type: typing.Type[SV1]
    operation_sedes: ssz.BaseSedes
    test_type: SV2
    # need the factory because the normal constructors don't allow positional arguments
    test_type_factory: typing.Callable[[uint16, SV1], SV2]
    test_sedes: ssz.BaseSedes
    ssz_file_names: typing.Sequence[str]

OperationRegistry = typing.NewType("OperationRegistry", typing.Dict[str,OperationRegistryEntry])



STATE_SSZ_FILE_NAMES = ("pre.ssz", "post.ssz")



def main(argv=None):
    logging.basicConfig(level=logging.INFO)
    op_registry = load_builtin_registry()
    args = get_args(argv, op_registry.keys())
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    try:
        op_details = op_registry[args.operation_name]
    except KeyError as e:
        raise ValueError(f"Operation name '{args.operation_name}' not supported.") from e

    op_dest =  args.out_dir or pathlib.Path(op_details.name+"_corpora")
    if args.force:
        # TODO print warning and wait for user confirmation?
        shutil.rmtree(op_dest, ignore_errors=True)

    op_dest.mkdir(parents=True, exist_ok=True)
    args.state_out_dir.mkdir(parents=True, exist_ok=True)

    state_mapping, next_id = get_existing_states(args.state_out_dir)
    num_states_pre = len(state_mapping)
    logging.info("Found %s existing states.", num_states_pre)
    state_mapping, next_id = collect_found_states(args.search_root, args.state_out_dir, state_mapping, next_id)
    logging.info("Found and imported %s new states.", len(state_mapping) - num_states_pre)

    num_tests = 0
    for op in get_operations(args.search_root, op_details):
        # Combine with every possible state
        for state_id in state_mapping.values():
            test_case = op_details.test_type_factory(state_id, op)
            #logging.debug("Created test case: %r", test_case)
            raw = serialize(test_case)

            # libfuzzer also uses sha1 names!
            out_path = op_dest / hashlib.sha1(raw).hexdigest()
            # this protects against duplicate test cases

            logging.debug("Saving to %s", out_path)

            out_path.write_bytes(raw)
            num_tests += 1
    logging.info("Wrote %s test cases.", num_tests)

def get_args(argv=None, op_names: typing.Optional[typing.Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Extracts basic fuzzing corpora from eth2 operation spec tests. "
            "as described in https://github.com/ethereum/eth2.0-specs/tree/dev/specs/test_formats/operations")
    parser.add_argument("--search-root", type=pathlib.Path, default=".", help="Directory containing relevant ssz files. Defaults to pwd")
    parser.add_argument("--state-out-dir", type=pathlib.Path, default="./beaconstate", help="Output directory containing beaconstate ssz files.")
    parser.add_argument("operation_name", choices=op_names or None, help="Operation Name: The identifier of the operation test cases to extract and generate. See operation_registry.") 
    parser.add_argument("--out-dir", type=pathlib.Path, help="Output directory for operation corpora. Defaults to './<operation_name>_corpora'")
    parser.add_argument("--force", action="store_true", help="Replace output directories if they already exist. Generally not required.")
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output.")
    #parser.add_argument("--save_yaml", action="store_true", help="Save YAML files of the test cases.")
    return parser.parse_args(argv)


def get_operations(search_dir: pathlib.Path, op_details: OperationRegistryEntry) -> typing.Iterable[SSZType]:
    # TODO deduplication? Only an efficiency not correctness problem. SHA1 does dedup after this
    for f in recursive_iterfiles(search_dir):
        if f.name.lower() in  op_details.ssz_file_names:
            # TODO handle deserialization errors
            yield translate_value(op_details.operation_sedes.deserialize(f.read_bytes()), op_details.operation_type)


def get_existing_states(state_dir: pathlib.Path, condense_duplicates: bool = False, validate_states: bool = False) -> typing.Tuple[typing.Dict[bytes, uint16], uint16]:
    """Reads all files in the provided state directory.
    :returns: a tuple containing a mapping of SHA1 bytes of the states to filenames/state_ids, and the next available state_id
    :raises AssertionError: if directory contains unexpected filenames (that aren't a uint16).
    """
    if condense_duplicates:
        raise NotImplementedError
    highest_id = -1
    state_mapping = {}
    for state_f in state_dir.iterdir():
        if not state_f.is_file():
            logging.warning("Unexpected entry: %s, ignored", state_f)
            continue
        try:
            state_id = uint16(int(state_f.name))
        except ValueError as e:
            raise AssertionError from e

        if validate_states:
            raise NotImplementedError

        d = hashlib.sha1(state_f.read_bytes()).digest()
        assert d not in state_mapping
        # TODO condense existing duplicate states?
        state_mapping[d] = state_id
        highest_id = max(highest_id, state_id)
    return state_mapping, uint16(highest_id + 1)


def collect_found_states(search_root: pathlib.Path, state_dir: pathlib.Path, state_mapping: typing.Dict[bytes, uint16], next_id: uint16, state_file_names: typing.Iterable[str] = STATE_SSZ_FILE_NAMES, validate_states: bool = False) -> typing.Tuple[typing.Dict[bytes, uint16], uint16]:
    """Searches search_root for new state files based on file name.

    Saves any new files to state_dir.
    Returns an updated state_mapping and next_id.

    :raises ValueError: if ``state_dir/next_id`` points to an existing file.
        Or a file exists with ``int(filename) > next_id``.
        Some files may have been copied before this is checked.
    """
    state_names = set(state_file_names)
    state_files = (f for f in recursive_iterfiles(search_root) if f.name in state_names)
    for f in state_files:
        if validate_states:
            raise NotImplementedError
        d = hashlib.sha1(f.read_bytes()).digest()
        if d in state_mapping:
            logging.debug("Identical state already present for %s", f)
        if d not in state_mapping:
            dest = state_dir / str(next_id)
            if dest.exists():
                raise ValueError(f"File {dest} already exists.")
            shutil.copy(f, dest)
            state_mapping[d] = next_id
            next_id += 1
    return state_mapping, next_id


def recursive_iterfiles(path: pathlib.Path) -> typing.Iterable[pathlib.Path]:
    """Recurses through directory yielding files."""
    if not path.is_dir():
        raise ValueError("Input path should be a directory.")
    for p in path.iterdir():
        if p.is_file():
            yield p
        if p.is_dir():
            yield from recursive_iterfiles(p)


def load_builtin_registry() -> OperationRegistry:
    registry_entries = [
            OperationRegistryEntry(
                name="block",
                operation_type=spec.BeaconBlock,
                operation_sedes=translate_typ(spec.BeaconBlock),
                test_type=BlockTestCase,
                test_type_factory=lambda i, o: BlockTestCase(state_id=i, block=o),
                test_sedes=translate_typ(BlockTestCase),
                ssz_file_names=("block.ssz"),
                ),
            OperationRegistryEntry(
                name="block_header",
                operation_type=spec.BeaconBlock,
                operation_sedes=translate_typ(spec.BeaconBlock),
                test_type=BlockHeaderTestCase,
                test_type_factory=lambda i, o: BlockHeaderTestCase(state_id=i, block=o),
                test_sedes=translate_typ(BlockHeaderTestCase),
                ssz_file_names=("block.ssz"),
                ),
            OperationRegistryEntry(
                name="attestation",
                operation_type=spec.Attestation,
                operation_sedes=translate_typ(spec.Attestation),
                test_type=AttestationTestCase,
                test_type_factory=lambda i, o: AttestationTestCase(state_id=i, Attestation=o),
                test_sedes=translate_typ(AttestationTestCase),
                ssz_file_names=("attestation.ssz"),
                ),
    ]
    return OperationRegistry({r.name: r for r in registry_entries})

# Test case classes

class BlockTestCase(Container):
    state_id: uint16
    block: spec.BeaconBlock

# Same as BlockTestCase
BlockHeaderTestCase = BlockTestCase

class AttestationTestCase(Container):
    state_id: uint16
    attestation: spec.Attestation


if __name__ == "__main__":
    main()

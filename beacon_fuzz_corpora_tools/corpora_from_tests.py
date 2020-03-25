#! /usr/bin/env python3


"""A helper to create initial corpora from spec test cases.

Makes Test cases as defined in the TargetRegistry

Given some states and some other input, will generate all possible combinations of corpora.

Any new state files found will be appended to the ``--state-out-dir`` with a filename of
increasing number.

The content of existing state files will be compared by hash, so only new states will be appended.

Depends on Eth2.0 Python spec, so run it from a venv with the relevant spec version installed!
Ensure the spec version and spec test versions are the same!


Eth2.0 Spec tests for some versions have been generated incorrectly, so deserialization can fail.
The following instances of buggy tests are known:

v0.9.3
  - sanity/blocks/test_invalid_state_root - produces a BeaconBlock, should be a SignedBeaconBlock
"""

import argparse
import dataclasses
import fnmatch
import functools
import hashlib
import logging
import pathlib
import shutil
import sys
import typing

import packaging.specifiers
import packaging.version

try:
    import eth2spec
    from eth2spec.phase0 import spec
    from eth2spec.utils.ssz.ssz_impl import serialize
    from eth2spec.utils.ssz.ssz_typing import Container, uint16
except ImportError as e:
    raise RuntimeError(
        "You must install an appropriate version of the Eth2 PySpec."
    ) from e

try:
    import ssz
    from eth2spec.fuzzing.decoder import translate_typ, translate_value
    from eth2spec.utils.ssz.ssz_typing import SSZType

    _SSZ_BASE_TYPE = SSZType
    _USE_REMERKLEABLE = False

except ImportError:
    # In use from eth2spec v0.11.0
    # The import is just to check that it's here
    import remerkleable
    from eth2spec.utils.ssz.ssz_typing import View

    _SSZ_BASE_TYPE = View
    _USE_REMERKLEABLE = True


SV1 = typing.TypeVar("SV1", bound=_SSZ_BASE_TYPE)
SV2 = typing.TypeVar("SV2", bound=_SSZ_BASE_TYPE)


# Uncomment if you want to hard-code a default spec version if not otherwise detected
# DEFAULT_SPEC_VERSION = packaging.version.Version('0.9.3')
DEFAULT_SPEC_VERSION = None

try:
    SPEC_VERSION = packaging.version.Version(eth2spec.__version__)
except AttributeError:
    # Version needs to be manually specified for spec versions < 0.10.2.dev0
    SPEC_VERSION = None

# see https://github.com/ethereum/eth2.0-specs/blob/v0.9.3/specs/core/0_beacon-chain.md#signed-envelopes
_NO_SIGNED_ENVELOPE_VERSIONS = packaging.specifiers.SpecifierSet(">0.8.2,<0.9.3")

SUPPORTED_TARGETS = [
    "attestation",
    "attester_slashing",
    "block",
    "block_header",
    "deposit",
    "proposer_slashing",
    "voluntary_exit",
]

STATE_SSZ_FILE_NAMES = ("pre.ssz", "post.ssz")


@dataclasses.dataclass
class TargetRegistryEntry(typing.Generic[SV1, SV2]):
    name: str
    operation_type: typing.Type[SV1]
    deserialize_operation: typing.Callable[[bytes, bool], SV1]
    test_type: typing.Type[SV2]
    # need the factory because the dataclass constructors don't allow positional arguments
    test_type_factory: typing.Callable[[uint16, SV1], SV2]
    serialize_test_type: typing.Callable[[SV2], bytes]
    ssz_file_names: typing.Sequence[str]
    # One or more directories containing relevant test files
    # Should be relative to the root of the eth2.0-spec-tests repository
    # Can be globbed
    # Set to (".") if any directories beneath the search_root are allowed
    # TODO implement if the spec-tests contain files of the same name but different SSZ type
    # spec_test_root_dir: typing.Sequence[str]


@dataclasses.dataclass
class TargetRegistry:
    version: packaging.version.Version
    entries: typing.Mapping[str, TargetRegistryEntry]


_BUILTIN_TARGET_REGISTRY: typing.Optional[TargetRegistry] = None


def main(argv: typing.Optional[typing.Collection[str]] = None) -> int:
    args = get_args(argv, SUPPORTED_TARGETS)
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    if SPEC_VERSION and SPEC_VERSION != args.spec_version:
        logger.warning(
            "Detected eth2spec version is different to --spec-version parameter. "
            "Continuing but results may be unexpected."
        )
    spec_version = SPEC_VERSION or args.spec_version or DEFAULT_SPEC_VERSION
    if not spec_version:
        raise argparse.ArgumentError(
            None,
            "Unable to identify eth2spec version '--spec-version' argument required.",
        )
    op_details = get_target_definition(args.target_name, spec_version)

    op_dest = args.out_dir or pathlib.Path(op_details.name + "_corpora")
    if args.force:
        # TODO print warning and wait for user confirmation?
        shutil.rmtree(op_dest, ignore_errors=True)

    op_dest.mkdir(parents=True, exist_ok=True)
    args.state_out_dir.mkdir(parents=True, exist_ok=True)

    state_mapping, next_id = get_existing_states(args.state_out_dir)
    num_states_pre = len(state_mapping)
    logging.info("Found %s existing states.", num_states_pre)
    state_mapping, next_id = collect_found_states(
        args.search_root, args.state_out_dir, state_mapping, next_id
    )
    logging.info(
        "Found and imported %s new states.", len(state_mapping) - num_states_pre
    )

    test_names: typing.Set[str] = set()
    num_ops = 0
    for op in get_operations(
        args.search_root, op_details, continue_on_error=args.ignore_ssz_error
    ):
        num_ops += 1
        # Combine with every possible state
        for state_id in state_mapping.values():
            test_case = op_details.test_type_factory(state_id, op)
            logging.debug("Created test case: %s", test_case)
            raw = op_details.serialize_test_type(test_case)

            # libfuzzer also uses sha1 names!
            out_path = op_dest / hashlib.sha1(raw).hexdigest()
            # this protects against duplicate test cases

            logging.debug("Saving to %s", out_path)

            out_path.write_bytes(raw)
            test_names.add(out_path.name)
    logging.info(
        "Wrote %s unique test cases from %s unique operations and %s states.",
        len(test_names),
        num_ops,
        len(state_mapping),
    )
    return 0


def get_args(
    argv=None, target_names: typing.Optional[typing.Collection[str]] = None
) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Extracts basic fuzzing corpora from eth2 spec tests. "
        "as described in https://github.com/ethereum/eth2.0-specs/tree/dev/specs/test_formats/operations"
    )
    parser.add_argument(
        "--search-root",
        type=pathlib.Path,
        default=".",
        help="Directory containing relevant ssz files. Defaults to pwd",
    )
    parser.add_argument(
        "--state-out-dir",
        type=pathlib.Path,
        default="./beaconstate",
        help="Output directory containing beaconstate ssz files.",
    )
    parser.add_argument(
        "target_name",
        choices=target_names or None,
        help=(
            "The identifier of the test cases to extract and generate. "
            "See operation_registry. "
        ),
    )
    parser.add_argument(
        "--out-dir",
        type=pathlib.Path,
        help="Output directory for operation corpora. Defaults to './<target_name>_corpora'",
    )
    parser.add_argument(
        "--spec-version",
        type=packaging.version.Version,
        help=(
            "Version name of the current pyspec installed/targeted."
            "Should only be used for versions < 0.10.2.dev0"
        ),
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Replace output directories if they already exist. Generally not required.",
    )
    parser.add_argument(
        "--ignore-ssz-error",
        action="store_true",
        help="Don't halt processing if a SSZ deserialization error occurs. "
        "(Shouldn't occur for correct test cases).",
    )
    parser.add_argument("--verbose", action="store_true", help="Enable verbose output.")
    # parser.add_argument("--save_yaml", action="store_true", help="Save YAML files of the test cases.")
    return parser.parse_args(argv)


def get_target_definition(
    target_name: str,
    spec_version: packaging.version.Version,
    target_registry: typing.Optional[TargetRegistry] = None,
) -> TargetRegistryEntry:
    registry = target_registry or load_builtin_registry(spec_version)
    if spec_version != registry.version:
        raise ValueError(f"spec_version '{spec_version}' not supported by registry")
    try:
        return registry.entries[target_name]
    except KeyError as e:
        raise ValueError(f"Target name '{target_name}' not present in registry.") from e


def get_operations(
    search_dir: pathlib.Path, op_details: TargetRegistryEntry, continue_on_error: bool
) -> typing.Iterable[_SSZ_BASE_TYPE]:
    """Returns unique operations in the search directory.

    :param continue_on_error: Will continue if failing to deserialize.
    """
    # TODO deduplication? Only an efficiency not correctness problem. SHA1 does dedup after this
    seen_ops: typing.Set[bytes] = set()
    for f in recursive_iterfiles(search_dir):
        if any(
            map(functools.partial(fnmatch.fnmatch, f.name), op_details.ssz_file_names)
        ):
            # filename matches one of the ssz_file_names (allowing for unix-style wildcards)
            raw = f.read_bytes()
            raw_hash = hashlib.sha1(raw).digest()
            if raw_hash not in seen_ops:
                # TODO handle deserialization errors
                seen_ops.add(raw_hash)
                maybe_op = op_details.deserialize_operation(raw)
                if maybe_op is not None:
                    # Successful
                    yield maybe_op
                else:
                    logging.warning("Deserialization failed for %s", f)
                    if not continue_on_error:
                        raise RuntimeError("Deserialization failed.")


def get_existing_states(
    state_dir: pathlib.Path,
    condense_duplicates: bool = False,
    validate_states: bool = False,
) -> typing.Tuple[typing.Dict[bytes, uint16], uint16]:
    """Reads all files in the provided state directory.
    :returns: a tuple containing a mapping of SHA1 bytes of the states to filenames/state_ids, and the next available state_id
    :raises AssertionError: if directory contains unexpected filenames (that aren't a uint16).
    """
    if condense_duplicates:
        raise NotImplementedError
    highest_id = -1
    state_mapping: typing.Dict[bytes, int] = {}
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


def collect_found_states(
    search_root: pathlib.Path,
    state_dir: pathlib.Path,
    state_mapping: typing.Dict[bytes, uint16],
    next_id: uint16,
    state_file_names: typing.Iterable[str] = STATE_SSZ_FILE_NAMES,
    validate_states: bool = False,
) -> typing.Tuple[typing.Dict[bytes, uint16], uint16]:
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


def load_builtin_registry(spec_version: packaging.version.Version) -> TargetRegistry:
    global _BUILTIN_TARGET_REGISTRY
    if _BUILTIN_TARGET_REGISTRY and _BUILTIN_TARGET_REGISTRY.version == spec_version:
        return _BUILTIN_TARGET_REGISTRY
    # Each supported target has a factory function with a name of the form "_get_{NAME}_entry"
    registry_entries = {
        name: globals()[f"_get_{name}_entry"](spec_version)
        for name in SUPPORTED_TARGETS
    }
    registry = TargetRegistry(version=spec_version, entries=registry_entries)
    _BUILTIN_TARGET_REGISTRY = registry
    return registry


# Fuzzing target definitions


def _get_attestation_entry(spec_version: packaging.version.Version):
    class AttestationTestCase(Container):
        state_id: uint16
        attestation: spec.Attestation

    return TargetRegistryEntry(
        name="attestation",
        operation_type=spec.Attestation,
        deserialize_operation=_deserialize_op_factory(spec.Attestation),
        test_type=AttestationTestCase,
        test_type_factory=lambda i, o: AttestationTestCase(state_id=i, attestation=o),
        serialize_test_type=_serialize_test_type_fn,
        ssz_file_names=("attestation.ssz",),
    )


def _get_attester_slashing_entry(spec_version: packaging.version.Version):
    class AttesterSlashingTestCase(Container):
        state_id: uint16
        attester_slashing: spec.AttesterSlashing

    return TargetRegistryEntry(
        name="attester_slashing",
        operation_type=spec.AttesterSlashing,
        deserialize_operation=_deserialize_op_factory(spec.AttesterSlashing),
        test_type=AttesterSlashingTestCase,
        test_type_factory=lambda i, o: AttesterSlashingTestCase(
            state_id=i, attester_slashing=o
        ),
        serialize_test_type=_serialize_test_type_fn,
        ssz_file_names=("attester_slashing.ssz",),
    )


def _get_block_entry(spec_version: packaging.version.Version):
    if spec_version in _NO_SIGNED_ENVELOPE_VERSIONS:
        # Same as BlockHeaderTestCase
        block_type = spec.BeaconBlock
        block_names = ("block.ssz", "blocks_*.ssz")
    else:
        block_type = spec.SignedBeaconBlock
        # names like this are present in the sanity_blocks tests
        # NOTE, for
        block_names = ("blocks_*.ssz",)

    class BlockTestCase(Container):
        state_id: uint16
        block: block_type

    return TargetRegistryEntry(
        name="block",
        operation_type=block_type,
        deserialize_operation=_deserialize_op_factory(block_type),
        test_type=BlockTestCase,
        test_type_factory=lambda i, o: BlockTestCase(state_id=i, block=o),
        serialize_test_type=_serialize_test_type_fn,
        ssz_file_names=block_names,
    )


def _get_block_header_entry(spec_version: packaging.version.Version):
    class BlockHeaderTestCase(Container):
        state_id: uint16
        block: spec.BeaconBlock

    return TargetRegistryEntry(
        name="block_header",
        operation_type=spec.BeaconBlock,
        deserialize_operation=_deserialize_op_factory(spec.BeaconBlock),
        test_type=BlockHeaderTestCase,
        test_type_factory=lambda i, o: BlockHeaderTestCase(state_id=i, block=o),
        serialize_test_type=_serialize_test_type_fn,
        ssz_file_names=("block.ssz",),
    )


def _get_deposit_entry(spec_version: packaging.version.Version):
    class DepositTestCase(Container):
        state_id: uint16
        deposit: spec.Deposit

    return TargetRegistryEntry(
        name="deposit",
        operation_type=spec.Deposit,
        deserialize_operation=_deserialize_op_factory(spec.Deposit),
        test_type=DepositTestCase,
        test_type_factory=lambda i, o: DepositTestCase(state_id=i, deposit=o),
        serialize_test_type=_serialize_test_type_fn,
        ssz_file_names=("deposit.ssz",),
    )


def _get_proposer_slashing_entry(spec_version: packaging.version.Version):
    class ProposerSlashingTestCase(Container):
        state_id: uint16
        proposer_slashing: spec.ProposerSlashing

    return TargetRegistryEntry(
        name="proposer_slashing",
        operation_type=spec.ProposerSlashing,
        deserialize_operation=_deserialize_op_factory(spec.ProposerSlashing),
        test_type=ProposerSlashingTestCase,
        test_type_factory=lambda i, o: ProposerSlashingTestCase(
            state_id=i, proposer_slashing=o
        ),
        serialize_test_type=_serialize_test_type_fn,
        ssz_file_names=("proposer_slashing.ssz",),
    )


def _get_voluntary_exit_entry(spec_version: packaging.version.Version):

    if spec_version in _NO_SIGNED_ENVELOPE_VERSIONS:
        exit_type = spec.VoluntaryExit
    else:
        exit_type = spec.SignedVoluntaryExit

    class VoluntaryExitTestCase(Container):
        state_id: uint16
        exit: exit_type

    return TargetRegistryEntry(
        name="voluntary_exit",
        operation_type=exit_type,
        deserialize_operation=_deserialize_op_factory(exit_type),
        test_type=VoluntaryExitTestCase,
        test_type_factory=lambda i, o: VoluntaryExitTestCase(state_id=i, exit=o),
        serialize_test_type=_serialize_test_type_fn,
        ssz_file_names=("voluntary_exit.ssz",),
    )


def _serialize_test_type_fn(test_obj):
    return serialize(test_obj)


if _USE_REMERKLEABLE:

    def _deserialize_op_factory(op_type):
        # See remerkleable
        return op_type.decode_bytes


else:

    def _deserialize_op_factory(op_type):

        op_sedes = translate_typ(op_type)

        def deserialize_fun(data):
            try:
                return translate_value(op_sedes.deserialize(data), op_type,)
            except ssz.exceptions.DeserializationError as e:
                # NOTE: Spec tests are sometimes incorrect so this can fail, see top of script
                logging.debug("Deserialize error", exc_info=True)
                return None

        return deserialize_fun


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    sys.exit(main())

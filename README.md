# beacon-fuzz-corpora

These are SSZ fuzzing corpora designed for use with Sigma Prime's [Beacon fuzz](https://github.com/sigp/beacon-fuzz), an Eth2 differential fuzzer.


## Folder structure

Based on Eth2 specification [test formats](https://github.com/ethereum/eth2.0-specs/blob/dev/specs/test_formats/README.md):

`./<spec_version>/<config_name>/<fuzzing_target>/`

### `<spec_version>/`

E.g. `v0.8.3 == 0-8-3`

Corpora may be compatible with other versions, but should be merged into that versions directory.

Each spec version may only be supported by a specific version of the `beacon-fuzz` differential fuzzer.

See the `README.md` contained in each folder for more information, and details about the corpora formats.

### `<config_name>/`

As in https://github.com/ethereum/eth2.0-specs/blob/dev/specs/test_formats/README.md#config-name

E.g. `mainnet`

### `<fuzzing_target>/`


The fuzzing target that this is intended for.

NOTE: some corpora may be compatible with different targets (e.g. `block` and `block_header` both take a `BeaconBlock` as input), but we keep the corpora separate as the desired coverage is different.

#### Beaconstates

In addition to the listed targets, `beaconstate/` currently stores a list of usable `BeaconState`s that
that can be leveraged for additional input by `libFuzzer`.

The `BeaconState` is not currently fuzzed, but passed verbatim as a series of known good states. This will be changed as we target epoch state transition functions, for which `libFuzzer` will be fuzzing/mutating `BeaconState`s.

Files in here should be a SSZ representation of a `BeaconState`, with integer filenames. Only add additional files to the `beaconstate/` directory and don't modify or rename existing files,
as other corpora refer to them.

## Tools/scripts

```console
$ python -m venv venv
$ . venv/bin/activate
$ pip install .
$ cd /path/to/eth2.0-specs && make
$ pip install /path/to/eth2/test_libs/pyspec
$ pip install /path/to/eth2/test_libs/config_helpers
$ all_corpora_from_tests -h
$ corpora_from_tests -h
```

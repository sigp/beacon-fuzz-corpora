# eth2.0-fuzzing-corpora

These are SSZ fuzzing corpora designed for use with https://github.com/sigp/eth2.0-fuzzing

LLVM differential fuzzer.


## Folder structure

Based on Eth2 Specs test format: https://github.com/ethereum/eth2.0-specs/blob/dev/specs/test_formats/README.md

`./<spec_version>/<config_name>/<fuzzing_target>/`

### `<spec_version>/

E.g. `v0.8.3 == 0-8-3`

Corpora may be compatible with other versions, but should be merged into that versions directory.

Each spec version may only be supported by a specific version of the eth2.0-fuzzing differential fuzzer. 

See the README.md contained in this folder for more info, and info about the corpora formats.

### `<config_name>/`

As in https://github.com/ethereum/eth2.0-specs/blob/dev/specs/test_formats/README.md#config-name

E.g. mainnet

### `<fuzzing_target>/`


The fuzzing target that this is intended for.

NOTE: some corpora may be compatible with different targets
(e.g. `block` and `block_header` both take a BeaconBlock as input),
but we keep the corpora separate as the desired coverage is different.
It could be useful to regularly merge from other compatible corpora.

#### Beaconstates

In addition to the listed targets, `beaconstate/` currently stores a list of usable `BeaconState`s that
that can be used for additional input by the fuzzers.

The `BeaconState` is not currently fuzzed, but passed verbatim as a series of known good states.

Files in here should be a SSZ representation of a `BeaconState`, with integer filenames.
Only add additional files to the `beaconstate/` directory and don't modify or rename existing files,
as other corpora refer to them.

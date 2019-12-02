# Compatible fuzzer

Compatible with current head of `master` branch for https://github.com/sigp/beacon-fuzz (commit [32b6db2](https://github.com/sigp/beacon-fuzz/commit/32b6db205143b1dd574b1df5e39c3d2d0f474ed2))

# Corpora Structure

NOTE: `uint16` is used to allow for a reasonable number of test states, while keeping a small size.
Minimizing the size reduces the fuzzer's search space.

For the following, `state_id` is the filename of a relevant `BeaconState` in `./<preset>/beaconstate/`.

## `attestation/`

Attestation SSZ input in the following format:


```python

class AttestationTestCase(Container):
    state_id: uint16
    attestation: Attestation

```

## `attester_slashing/`

Attestation SSZ input in the following format:


```python

class AttesterSlashingTestCase(Container):
    state_id: uint16
    attester_slashing: AttesterSlashing

```

## `block_header/`

Block headers ssz input in the following format:


```python

class BlockHeaderTestCase(Container):
    state_id: uint16
    block: BeaconBlock

```

## `block/`

Block ssz input in the following format:


```python

class BlockTestCase(Container):
    state_id: uint16
    block: BeaconBlock

```

## `shuffle/`


Binary byte string to be shuffled

Interpreted as follows:


```python

# some binary blob, should at least 34 bytes long
raw_input = bytes.fromhex('deadbeef' * 12)

# the length of the list to be shuffled
shuffle_rounds = raw_input[0:2] % 100

# shuffle seed
seed = raw_input[2:34]

# rest of the data is ignored
```

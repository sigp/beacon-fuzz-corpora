# Compatible fuzzer

Compatible with current head of https://github.com/sigp/eth2.0-fuzzing

(As of 2019-10-20)

# Corpora Structure

NOTE: uint16 is used to allow for a reasonable number of test states, while keeping a small size.
Minimizing the size reduces the fuzzer's search space.

## `attestation/`

Block headers ssz input in the following format:


```python

class AttestationTestCase(Container):
    state_id: uint16
    block: Attestation

```

where `state_id` is the filename of a relevant `BeaconState` in `./<preset>/beaconstate/`.

## `block_header/`

Block headers ssz input in the following format:


```python

class BlockHeaderTestCase(Container):
    state_id: uint16
    block: BeaconBlock

```

where `state_id` is the filename of a relevant `BeaconState` in `./<preset>/beaconstate/`.

## `block/`

Block ssz input in the following format:


```python

class BlockTestCase(Container):
    state_id: uint16
    block: BeaconBlock

```

where `state_id` is the filename of a relevant `BeaconState` in `./<preset>/beaconstate/`.

## `shuffle/`


Binary byte string to be shuffled

TODO is this little endian or big?

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

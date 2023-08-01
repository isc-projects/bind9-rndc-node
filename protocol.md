# RNDC Protocol Details

## High-level Data Exchange

The RNDC protocol uses a seralised binary representation of a "symbol
expression", where the top level entity is a table of key/value pairs,
and where values may be further nested tables, or lists of values, or a
single value.

To avoid replay attacks the top level table always contains a `_ctrl`
key, with subkeys of `_tim`, `_exp` and `_ser`. `_tim` and `_exp` set
the time validity of the current message (in UNIX epoch time), and
`_ser` contains a random number that increments in each message. All of
the numbers are transferred as ASCII decimal integers.

RNDC requires that the client and server also exchange a nonce (also
usually an ASCII-formatted decimal) before any real commands may be
sent. The client sends a message containing `{_data: {type: 'null'}}`
and the server sends back the nonce within the `_nonce` subkey of the
`_ctrl` table. The client then also adds this nonce in subsequent
messages to the server.

Once the nonce has been negotiated, RNDC commands are sent within a
message containing `{_data: {type: "command contents"}}` and the
response is found in the server's `{_data: ...}` message in the `result`
and (optionally) `text` sub-fields. Replies also contain a key of `_rpl`
with a value of `1`.

## Authentication

Message authentication is achieved by adding an entry named `_auth` as
the first entry in the top level table, with that entry's value being a
single-entry table itself containing a key of either `hmd5` or `hsha`
and value being the HMAC digest in Base64 format _over the remainder of
the serialised packet_.

For MD5 signatures the trailing padding characters ('=') are removed,
given a total digest length of 22 octets. Otherwise, if the HMAC
algorithm is from the SHA family the digest is preceded with a single
byte indicating the algorithm (SHA-1 = 161, SHA-224 = 162, SHA-256 =
163, SHA-384 = 164, SHA-512 = 165) and the digest is NUL padded to a
length of 88 octets.

The simplest approach to create a signed packet is to serialise the data
to be signed without its 5 byte header, and then calculate the signature
over that, and then create a new table containing `{_auth: {[type]:
signature}}` and serialise that, again without its 5 byte header. The
required output is then the concatenation of:
```
<length><version><serialised signature><serialised data>
```

## Example Messages

An example exchange for an "rndc status" command is shown here:
```
send {
  _auth: { hmd5: 'bHxzFsGwVVLcYDlg4yZVHQ' } },
  _ctrl: { _ser: '1781968185', _tim: '1447079445', _exp: '1447079505' } },
  _data: { type: 'null' }
}
recv {
  _auth: { hmd5: '31ESy9s0SolvJoxxQFjIcg' },
  _ctrl: { _ser: '1781968185', _tim: '1447079445', _exp: '1447079505', _rpl: '1', _nonce: '129203136' },
  _data: { type: 'null', result: '0' }
}
send {
  _auth: { hmd5: 'If7u+rdq7Fbb+xDGuNQn6w' } },
  _ctrl: { _nonce: '129203136', _ser: '1781968186', _tim: '1447079445', _exp: '1447079505' },
  _data: { type: 'status' }
}
recv {
  _auth: { hmd5: '6vUCcrpmOFDn8Jzq1ZDsyA' },
  _ctrl: { _ser: '1781968186', _tim: '1447079445', _exp: '1447079505', _rpl: '1', _nonce: '129203136' },
  _data: { type: 'status', result: '0', text: 'version: BIND 9.11.0pre-alpha <id:9d55785> ...\nserver is up and running' }
}
```

### Packet Binary Encoding

An RNDC packet is encoded as a four byte length field, a four byte
version field (currently version 0x00000001) and then a table of
key/value pairs encoded as below but _without_ either the `type` or
`length` fields i.e. just the raw key/value data. The packet's length
field includes the size of the version field. All multibyte values are
transmitted in network order.

### Value Binary Encoding

All values are encoded as a single byte `type` field, a four byte
`length` field, followed by the actual data:

```
 +--------+--------+--------+--------+
 |  TYPE  |LEN(MSB)|   ...  |   ...  |
 +--------+--------+--------+--------+
 |LEN(LSB)| DATA_0 |   ...  |       
 +--------+--------+--------+
```

#### String

Type = 0 - unused in BIND

#### Binary Data

Type = 1

The data is just the raw binary data

#### Table

Type = 2

The data is formed by concatenating key/value pairs, where each key is
encoded as <length byte><name...> and the values are encoded
per this section according to their type.

#### List

Type = 3

The data is formed by concatenating the list's values, each individually
encoded per this section according to their type.

# Structwrapping

[![Godoc](https://godoc.org/github.com/hashicorp/go-kms-wrapping/structwrapping?status.svg)](https://godoc.org/github.com/hashicorp/go-kms-wrapping/structwrapping)

`structwrapping` provides a convenience package for dealing with encrypted
values in structs in an automated way. This can be used for e.g. performing
encryption and decryption before sending to and when retrieving values from a
database, via a hook/middleware. 

Caveats:

* The input must be a pointer to a struct
* Tags must be balanced (there must be a matching ct tag entry with the same
  identifier as a pt tag entry, and vice versa)
* This does not currently recurse
* Currently there is no checking for overwriting of values, although this may
  change

## Usage

Add struct tags that specify fields for wrapping. Wrapping tags must contain:

* A field type of `pt` (plaintext) or `ct` (ciphertext) 
* A unique name that ties together a pair of `pt` and `ct` fields 

This unique name does _not_ need to match the name of a struct field; this is
on purpose, so that struct fields can be renamed without breaking this
functionality.

The best way to see how to use the package is via one of the tests for this
package, reproduced below:
```go
var err error
type sutStruct struct {
    PT1 []byte                      `wrapping:"pt,foo"`
    CT1 *wrapping.EncryptedBlobInfo `wrapping:"ct,foo"`

    PT2 []byte                      `wrapping:"pt,bar"`
    CT2 *wrapping.EncryptedBlobInfo `wrapping:"ct,bar"`
}

sut := &sutStruct{PT1: []byte("foo"), PT2: []byte("bar")}
err = WrapStruct(nil, wrapper, sut, nil)
assert.Nil(t, err)
assert.NotNil(t, sut.CT1)
assert.NotNil(t, sut.CT2)

fooVal, err := wrapper.Decrypt(nil, sut.CT1, nil)
assert.Nil(t, err)
assert.Equal(t, fooVal, []byte("foo"))

barVal, err := wrapper.Decrypt(nil, sut.CT2, nil)
assert.Nil(t, err)
assert.Equal(t, barVal, []byte("bar"))

sut2 := &sutStruct{CT1: sut.CT1, CT2: sut.CT2}
err = UnwrapStruct(nil, wrapper, sut2, nil)
assert.Nil(t, err)
assert.Equal(t, sut2.PT1, []byte("foo"))
assert.Equal(t, sut2.PT2, []byte("bar"))
```

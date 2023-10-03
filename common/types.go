// Copyright 2015 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package common

import (
	"bytes"
	"database/sql/driver"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"math/rand"
	"reflect"
	"strings"

	apiv1 "github.com/attestantio/go-builder-client/api/v1"
	consensusbellatrix "github.com/attestantio/go-eth2-client/spec/bellatrix"
	consensuscapella "github.com/attestantio/go-eth2-client/spec/capella"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/ethereum/go-ethereum/common/hexutil"
	ssz "github.com/ferranbt/fastssz"
	"golang.org/x/crypto/sha3"
)

// Lengths of hashes and addresses in bytes.
const (
	// HashLength is the expected length of the hash
	HashLength = 32
	// AddressLength is the expected length of the address
	AddressLength = 20
)

var (
	hashT    = reflect.TypeOf(Hash{})
	addressT = reflect.TypeOf(Address{})
)

// Hash represents the 32 byte Keccak256 hash of arbitrary data.
type Hash [HashLength]byte

// BytesToHash sets b to hash.
// If b is larger than len(h), b will be cropped from the left.
func BytesToHash(b []byte) Hash {
	var h Hash
	h.SetBytes(b)
	return h
}

// BigToHash sets byte representation of b to hash.
// If b is larger than len(h), b will be cropped from the left.
func BigToHash(b *big.Int) Hash { return BytesToHash(b.Bytes()) }

// HexToHash sets byte representation of s to hash.
// If b is larger than len(h), b will be cropped from the left.
func HexToHash(s string) Hash { return BytesToHash(FromHex(s)) }

// Bytes gets the byte representation of the underlying hash.
func (h Hash) Bytes() []byte { return h[:] }

// Big converts a hash to a big integer.
func (h Hash) Big() *big.Int { return new(big.Int).SetBytes(h[:]) }

// Hex converts a hash to a hex string.
func (h Hash) Hex() string { return hexutil.Encode(h[:]) }

// TerminalString implements log.TerminalStringer, formatting a string for console
// output during logging.
func (h Hash) TerminalString() string {
	return fmt.Sprintf("%x..%x", h[:3], h[29:])
}

// String implements the stringer interface and is used also by the logger when
// doing full logging into a file.
func (h Hash) String() string {
	return h.Hex()
}

// Format implements fmt.Formatter.
// Hash supports the %v, %s, %q, %x, %X and %d format verbs.
func (h Hash) Format(s fmt.State, c rune) {
	hexb := make([]byte, 2+len(h)*2)
	copy(hexb, "0x")
	hex.Encode(hexb[2:], h[:])

	switch c {
	case 'x', 'X':
		if !s.Flag('#') {
			hexb = hexb[2:]
		}
		if c == 'X' {
			hexb = bytes.ToUpper(hexb)
		}
		fallthrough
	case 'v', 's':
		s.Write(hexb)
	case 'q':
		q := []byte{'"'}
		s.Write(q)
		s.Write(hexb)
		s.Write(q)
	case 'd':
		fmt.Fprint(s, ([len(h)]byte)(h))
	default:
		fmt.Fprintf(s, "%%!%c(hash=%x)", c, h)
	}
}

// UnmarshalText parses a hash in hex syntax.
func (h *Hash) UnmarshalText(input []byte) error {
	return hexutil.UnmarshalFixedText("Hash", input, h[:])
}

// UnmarshalJSON parses a hash in hex syntax.
func (h *Hash) UnmarshalJSON(input []byte) error {
	return hexutil.UnmarshalFixedJSON(hashT, input, h[:])
}

// MarshalText returns the hex representation of h.
func (h Hash) MarshalText() ([]byte, error) {
	return hexutil.Bytes(h[:]).MarshalText()
}

// SetBytes sets the hash to the value of b.
// If b is larger than len(h), b will be cropped from the left.
func (h *Hash) SetBytes(b []byte) {
	if len(b) > len(h) {
		b = b[len(b)-HashLength:]
	}

	copy(h[HashLength-len(b):], b)
}

// Generate implements testing/quick.Generator.
func (h Hash) Generate(rand *rand.Rand, size int) reflect.Value {
	m := rand.Intn(len(h))
	for i := len(h) - 1; i > m; i-- {
		h[i] = byte(rand.Uint32())
	}
	return reflect.ValueOf(h)
}

// Scan implements Scanner for database/sql.
func (h *Hash) Scan(src interface{}) error {
	srcB, ok := src.([]byte)
	if !ok {
		return fmt.Errorf("can't scan %T into Hash", src)
	}
	if len(srcB) != HashLength {
		return fmt.Errorf("can't scan []byte of len %d into Hash, want %d", len(srcB), HashLength)
	}
	copy(h[:], srcB)
	return nil
}

// Value implements valuer for database/sql.
func (h Hash) Value() (driver.Value, error) {
	return h[:], nil
}

// ImplementsGraphQLType returns true if Hash implements the specified GraphQL type.
func (Hash) ImplementsGraphQLType(name string) bool { return name == "Bytes32" }

// UnmarshalGraphQL unmarshals the provided GraphQL query data.
func (h *Hash) UnmarshalGraphQL(input interface{}) error {
	var err error
	switch input := input.(type) {
	case string:
		err = h.UnmarshalText([]byte(input))
	default:
		err = fmt.Errorf("unexpected type %T for Hash", input)
	}
	return err
}

// UnprefixedHash allows marshaling a Hash without 0x prefix.
type UnprefixedHash Hash

// UnmarshalText decodes the hash from hex. The 0x prefix is optional.
func (h *UnprefixedHash) UnmarshalText(input []byte) error {
	return hexutil.UnmarshalFixedUnprefixedText("UnprefixedHash", input, h[:])
}

// MarshalText encodes the hash as hex.
func (h UnprefixedHash) MarshalText() ([]byte, error) {
	return []byte(hex.EncodeToString(h[:])), nil
}

/////////// Address

// Address represents the 20 byte address of an Ethereum account.
type Address [AddressLength]byte

// BytesToAddress returns Address with value b.
// If b is larger than len(h), b will be cropped from the left.
func BytesToAddress(b []byte) Address {
	var a Address
	a.SetBytes(b)
	return a
}

// BigToAddress returns Address with byte values of b.
// If b is larger than len(h), b will be cropped from the left.
func BigToAddress(b *big.Int) Address { return BytesToAddress(b.Bytes()) }

// HexToAddress returns Address with byte values of s.
// If s is larger than len(h), s will be cropped from the left.
func HexToAddress(s string) Address { return BytesToAddress(FromHex(s)) }

// IsHexAddress verifies whether a string can represent a valid hex-encoded
// Ethereum address or not.
func IsHexAddress(s string) bool {
	if has0xPrefix(s) {
		s = s[2:]
	}
	return len(s) == 2*AddressLength && isHex(s)
}

// Bytes gets the string representation of the underlying address.
func (a Address) Bytes() []byte { return a[:] }

// Hash converts an address to a hash by left-padding it with zeros.
func (a Address) Hash() Hash { return BytesToHash(a[:]) }

// Big converts an address to a big integer.
func (a Address) Big() *big.Int { return new(big.Int).SetBytes(a[:]) }

// Hex returns an EIP55-compliant hex string representation of the address.
func (a Address) Hex() string {
	return string(a.checksumHex())
}

// String implements fmt.Stringer.
func (a Address) String() string {
	return a.Hex()
}

func (a *Address) checksumHex() []byte {
	buf := a.hex()

	// compute checksum
	sha := sha3.NewLegacyKeccak256()
	sha.Write(buf[2:])
	hash := sha.Sum(nil)
	for i := 2; i < len(buf); i++ {
		hashByte := hash[(i-2)/2]
		if i%2 == 0 {
			hashByte = hashByte >> 4
		} else {
			hashByte &= 0xf
		}
		if buf[i] > '9' && hashByte > 7 {
			buf[i] -= 32
		}
	}
	return buf[:]
}

func (a Address) hex() []byte {
	var buf [len(a)*2 + 2]byte
	copy(buf[:2], "0x")
	hex.Encode(buf[2:], a[:])
	return buf[:]
}

// Format implements fmt.Formatter.
// Address supports the %v, %s, %q, %x, %X and %d format verbs.
func (a Address) Format(s fmt.State, c rune) {
	switch c {
	case 'v', 's':
		s.Write(a.checksumHex())
	case 'q':
		q := []byte{'"'}
		s.Write(q)
		s.Write(a.checksumHex())
		s.Write(q)
	case 'x', 'X':
		// %x disables the checksum.
		hex := a.hex()
		if !s.Flag('#') {
			hex = hex[2:]
		}
		if c == 'X' {
			hex = bytes.ToUpper(hex)
		}
		s.Write(hex)
	case 'd':
		fmt.Fprint(s, ([len(a)]byte)(a))
	default:
		fmt.Fprintf(s, "%%!%c(address=%x)", c, a)
	}
}

// SetBytes sets the address to the value of b.
// If b is larger than len(a), b will be cropped from the left.
func (a *Address) SetBytes(b []byte) {
	if len(b) > len(a) {
		b = b[len(b)-AddressLength:]
	}
	copy(a[AddressLength-len(b):], b)
}

// MarshalText returns the hex representation of a.
func (a Address) MarshalText() ([]byte, error) {
	return hexutil.Bytes(a[:]).MarshalText()
}

// UnmarshalText parses a hash in hex syntax.
func (a *Address) UnmarshalText(input []byte) error {
	return hexutil.UnmarshalFixedText("Address", input, a[:])
}

// UnmarshalJSON parses a hash in hex syntax.
func (a *Address) UnmarshalJSON(input []byte) error {
	return hexutil.UnmarshalFixedJSON(addressT, input, a[:])
}

// Scan implements Scanner for database/sql.
func (a *Address) Scan(src interface{}) error {
	srcB, ok := src.([]byte)
	if !ok {
		return fmt.Errorf("can't scan %T into Address", src)
	}
	if len(srcB) != AddressLength {
		return fmt.Errorf("can't scan []byte of len %d into Address, want %d", len(srcB), AddressLength)
	}
	copy(a[:], srcB)
	return nil
}

// Value implements valuer for database/sql.
func (a Address) Value() (driver.Value, error) {
	return a[:], nil
}

// ImplementsGraphQLType returns true if Hash implements the specified GraphQL type.
func (a Address) ImplementsGraphQLType(name string) bool { return name == "Address" }

// UnmarshalGraphQL unmarshals the provided GraphQL query data.
func (a *Address) UnmarshalGraphQL(input interface{}) error {
	var err error
	switch input := input.(type) {
	case string:
		err = a.UnmarshalText([]byte(input))
	default:
		err = fmt.Errorf("unexpected type %T for Address", input)
	}
	return err
}

// UnprefixedAddress allows marshaling an Address without 0x prefix.
type UnprefixedAddress Address

// UnmarshalText decodes the address from hex. The 0x prefix is optional.
func (a *UnprefixedAddress) UnmarshalText(input []byte) error {
	return hexutil.UnmarshalFixedUnprefixedText("UnprefixedAddress", input, a[:])
}

// MarshalText encodes the address as hex.
func (a UnprefixedAddress) MarshalText() ([]byte, error) {
	return []byte(hex.EncodeToString(a[:])), nil
}

// MixedcaseAddress retains the original string, which may or may not be
// correctly checksummed
type MixedcaseAddress struct {
	addr     Address
	original string
}

// NewMixedcaseAddress constructor (mainly for testing)
func NewMixedcaseAddress(addr Address) MixedcaseAddress {
	return MixedcaseAddress{addr: addr, original: addr.Hex()}
}

// NewMixedcaseAddressFromString is mainly meant for unit-testing
func NewMixedcaseAddressFromString(hexaddr string) (*MixedcaseAddress, error) {
	if !IsHexAddress(hexaddr) {
		return nil, errors.New("invalid address")
	}
	a := FromHex(hexaddr)
	return &MixedcaseAddress{addr: BytesToAddress(a), original: hexaddr}, nil
}

// UnmarshalJSON parses MixedcaseAddress
func (ma *MixedcaseAddress) UnmarshalJSON(input []byte) error {
	if err := hexutil.UnmarshalFixedJSON(addressT, input, ma.addr[:]); err != nil {
		return err
	}
	return json.Unmarshal(input, &ma.original)
}

// MarshalJSON marshals the original value
func (ma *MixedcaseAddress) MarshalJSON() ([]byte, error) {
	if strings.HasPrefix(ma.original, "0x") || strings.HasPrefix(ma.original, "0X") {
		return json.Marshal(fmt.Sprintf("0x%s", ma.original[2:]))
	}
	return json.Marshal(fmt.Sprintf("0x%s", ma.original))
}

// Address returns the address
func (ma *MixedcaseAddress) Address() Address {
	return ma.addr
}

// String implements fmt.Stringer
func (ma *MixedcaseAddress) String() string {
	if ma.ValidChecksum() {
		return fmt.Sprintf("%s [chksum ok]", ma.original)
	}
	return fmt.Sprintf("%s [chksum INVALID]", ma.original)
}

// ValidChecksum returns true if the address has valid checksum
func (ma *MixedcaseAddress) ValidChecksum() bool {
	return ma.original == ma.addr.Hex()
}

// Original returns the mixed-case input string
func (ma *MixedcaseAddress) Original() string {
	return ma.original
}

/*
SubmitBlockRequestV2Optimistic is the v2 request from the builder to submit
a block. The message must be SSZ encoded. The first three fields are at most
944 bytes, which fit into a single 1500 MTU ethernet packet. The
`UnmarshalSSZHeaderOnly` function just parses the first three fields,
which is sufficient data to set the bid of the builder. The `Transactions`
and `Withdrawals` fields are required to construct the full SignedBeaconBlock
and are parsed asynchronously.

Header only layout:
[000-236) = Message   (236 bytes)
[236-240) = offset1   (  4 bytes)
[240-336) = Signature ( 96 bytes)
[336-340) = offset2   (  4 bytes)
[340-344) = offset3   (  4 bytes)
[344-944) = EPH       (600 bytes)
*/
type SubmitBlockRequestV2Optimistic struct {
	Message                *apiv1.BidTrace
	ExecutionPayloadHeader *consensuscapella.ExecutionPayloadHeader
	Signature              phase0.BLSSignature              `ssz-size:"96"`
	Transactions           []consensusbellatrix.Transaction `ssz-max:"1048576,1073741824" ssz-size:"?,?"`
	Withdrawals            []*consensuscapella.Withdrawal   `ssz-max:"16"`
}

// MarshalSSZ ssz marshals the SubmitBlockRequestV2Optimistic object
func (s *SubmitBlockRequestV2Optimistic) MarshalSSZ() ([]byte, error) {
	return ssz.MarshalSSZ(s)
}

// UnmarshalSSZ ssz unmarshals the SubmitBlockRequestV2Optimistic object
func (s *SubmitBlockRequestV2Optimistic) UnmarshalSSZ(buf []byte) error {
	var err error
	size := uint64(len(buf))
	if size < 344 {
		return ssz.ErrSize
	}

	tail := buf
	var o1, o3, o4 uint64

	// Field (0) 'Message'
	if s.Message == nil {
		s.Message = new(apiv1.BidTrace)
	}
	if err = s.Message.UnmarshalSSZ(buf[0:236]); err != nil {
		return err
	}

	// Offset (1) 'ExecutionPayloadHeader'
	if o1 = ssz.ReadOffset(buf[236:240]); o1 > size {
		return ssz.ErrOffset
	}

	if o1 < 344 {
		return ssz.ErrInvalidVariableOffset
	}

	// Field (2) 'Signature'
	copy(s.Signature[:], buf[240:336])

	// Offset (3) 'Transactions'
	if o3 = ssz.ReadOffset(buf[336:340]); o3 > size || o1 > o3 {
		return ssz.ErrOffset
	}

	// Offset (4) 'Withdrawals'
	if o4 = ssz.ReadOffset(buf[340:344]); o4 > size || o3 > o4 {
		return ssz.ErrOffset
	}

	// Field (1) 'ExecutionPayloadHeader'
	{
		buf = tail[o1:o3]
		if s.ExecutionPayloadHeader == nil {
			s.ExecutionPayloadHeader = new(consensuscapella.ExecutionPayloadHeader)
		}
		if err = s.ExecutionPayloadHeader.UnmarshalSSZ(buf); err != nil {
			return err
		}
	}

	// Field (3) 'Transactions'
	{
		buf = tail[o3:o4]
		num, err := ssz.DecodeDynamicLength(buf, 1073741824)
		if err != nil {
			return err
		}
		s.Transactions = make([]consensusbellatrix.Transaction, num)
		err = ssz.UnmarshalDynamic(buf, num, func(indx int, buf []byte) (err error) {
			if len(buf) > 1073741824 {
				return ssz.ErrBytesLength
			}
			if cap(s.Transactions[indx]) == 0 {
				s.Transactions[indx] = consensusbellatrix.Transaction(make([]byte, 0, len(buf)))
			}
			s.Transactions[indx] = append(s.Transactions[indx], buf...)
			return nil
		})
		if err != nil {
			return err
		}
	}

	// Field (4) 'Withdrawals'
	{
		buf = tail[o4:]
		num, err := ssz.DivideInt2(len(buf), 44, 16)
		if err != nil {
			return err
		}
		s.Withdrawals = make([]*consensuscapella.Withdrawal, num)
		for ii := 0; ii < num; ii++ {
			if s.Withdrawals[ii] == nil {
				s.Withdrawals[ii] = new(consensuscapella.Withdrawal)
			}
			if err = s.Withdrawals[ii].UnmarshalSSZ(buf[ii*44 : (ii+1)*44]); err != nil {
				return err
			}
		}
	}
	return err
}

// UnmarshalSSZHeaderOnly ssz unmarshals the first 3 fields of the SubmitBlockRequestV2Optimistic object
func (s *SubmitBlockRequestV2Optimistic) UnmarshalSSZHeaderOnly(buf []byte) error {
	var err error
	size := uint64(len(buf))
	if size < 344 {
		return ssz.ErrSize
	}

	tail := buf
	var o1, o3 uint64

	// Field (0) 'Message'
	if s.Message == nil {
		s.Message = new(apiv1.BidTrace)
	}
	if err = s.Message.UnmarshalSSZ(buf[0:236]); err != nil {
		return err
	}

	// Offset (1) 'ExecutionPayloadHeader'
	if o1 = ssz.ReadOffset(buf[236:240]); o1 > size {
		return ssz.ErrOffset
	}

	if o1 < 344 {
		return ssz.ErrInvalidVariableOffset
	}

	// Field (2) 'Signature'
	copy(s.Signature[:], buf[240:336])

	// Offset (3) 'Transactions'
	if o3 = ssz.ReadOffset(buf[336:340]); o3 > size || o1 > o3 {
		return ssz.ErrOffset
	}

	// Field (1) 'ExecutionPayloadHeader'
	{
		buf = tail[o1:o3]
		if s.ExecutionPayloadHeader == nil {
			s.ExecutionPayloadHeader = new(consensuscapella.ExecutionPayloadHeader)
		}
		if err = s.ExecutionPayloadHeader.UnmarshalSSZ(buf); err != nil {
			return err
		}
	}
	return err
}

// MarshalSSZTo ssz marshals the SubmitBlockRequestV2Optimistic object to a target array
func (s *SubmitBlockRequestV2Optimistic) MarshalSSZTo(buf []byte) (dst []byte, err error) {
	dst = buf
	offset := int(344)

	// Field (0) 'Message'
	if s.Message == nil {
		s.Message = new(apiv1.BidTrace)
	}
	if dst, err = s.Message.MarshalSSZTo(dst); err != nil {
		return
	}

	// Offset (1) 'ExecutionPayloadHeader'
	dst = ssz.WriteOffset(dst, offset)
	if s.ExecutionPayloadHeader == nil {
		s.ExecutionPayloadHeader = new(consensuscapella.ExecutionPayloadHeader)
	}
	offset += s.ExecutionPayloadHeader.SizeSSZ()

	// Field (2) 'Signature'
	dst = append(dst, s.Signature[:]...)

	// Offset (3) 'Transactions'
	dst = ssz.WriteOffset(dst, offset)
	for ii := 0; ii < len(s.Transactions); ii++ {
		offset += 4
		offset += len(s.Transactions[ii])
	}

	// Offset (4) 'Withdrawals'
	dst = ssz.WriteOffset(dst, offset)

	// Field (1) 'ExecutionPayloadHeader'
	if dst, err = s.ExecutionPayloadHeader.MarshalSSZTo(dst); err != nil {
		return
	}

	// Field (3) 'Transactions'
	if size := len(s.Transactions); size > 1073741824 {
		err = ssz.ErrListTooBigFn("SubmitBlockRequestV2Optimistic.Transactions", size, 1073741824)
		return
	}
	{
		offset = 4 * len(s.Transactions)
		for ii := 0; ii < len(s.Transactions); ii++ {
			dst = ssz.WriteOffset(dst, offset)
			offset += len(s.Transactions[ii])
		}
	}
	for ii := 0; ii < len(s.Transactions); ii++ {
		if size := len(s.Transactions[ii]); size > 1073741824 {
			err = ssz.ErrBytesLengthFn("SubmitBlockRequestV2Optimistic.Transactions[ii]", size, 1073741824)
			return
		}
		dst = append(dst, s.Transactions[ii]...)
	}

	// Field (4) 'Withdrawals'
	if size := len(s.Withdrawals); size > 16 {
		err = ssz.ErrListTooBigFn("SubmitBlockRequestV2Optimistic.Withdrawals", size, 16)
		return
	}
	for ii := 0; ii < len(s.Withdrawals); ii++ {
		if dst, err = s.Withdrawals[ii].MarshalSSZTo(dst); err != nil {
			return
		}
	}
	return dst, nil
}

// SizeSSZ returns the ssz encoded size in bytes for the SubmitBlockRequestV2Optimistic object
func (s *SubmitBlockRequestV2Optimistic) SizeSSZ() (size int) {
	size = 344

	// Field (1) 'ExecutionPayloadHeader'
	if s.ExecutionPayloadHeader == nil {
		s.ExecutionPayloadHeader = new(consensuscapella.ExecutionPayloadHeader)
	}
	size += s.ExecutionPayloadHeader.SizeSSZ()

	// Field (3) 'Transactions'
	for ii := 0; ii < len(s.Transactions); ii++ {
		size += 4
		size += len(s.Transactions[ii])
	}

	// Field (4) 'Withdrawals'
	size += len(s.Withdrawals) * 44

	return
}

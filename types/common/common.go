package common

import (
	"math/big"

	api "github.com/ethereum/go-ethereum/beacon/engine"
	el_common "github.com/ethereum/go-ethereum/common"
	blsu "github.com/protolambda/bls12-381-util"
	"github.com/protolambda/zrnt/eth2/beacon/common"
	beacon "github.com/protolambda/zrnt/eth2/beacon/common"
	"github.com/protolambda/zrnt/eth2/beacon/deneb"
	"github.com/protolambda/ztyp/tree"
	"github.com/protolambda/ztyp/view"
)

type ValidatorRegistrationV1 struct {
	FeeRecipient common.Eth1Address `json:"fee_recipient" yaml:"fee_recipient"`
	GasLimit     view.Uint64View    `json:"gas_limit"     yaml:"gas_limit"`
	Timestamp    view.Uint64View    `json:"timestamp"     yaml:"timestamp"`
	PubKey       common.BLSPubkey   `json:"pubkey"        yaml:"pubkey"`
}

func (vr *ValidatorRegistrationV1) HashTreeRoot(hFn tree.HashFn) tree.Root {
	return hFn.HashTreeRoot(
		&vr.FeeRecipient,
		&vr.GasLimit,
		&vr.Timestamp,
		&vr.PubKey,
	)
}

type SignedValidatorRegistrationV1 struct {
	Message   ValidatorRegistrationV1 `json:"message"   yaml:"message"`
	Signature common.BLSSignature     `json:"signature" yaml:"signature"`
}

type BuilderBidContext struct {
	ParentBlockRoot tree.Root
	Slot            beacon.Slot
	ProposerIndex   beacon.ValidatorIndex
}

type BuilderBid interface {
	Build(*beacon.Spec, *api.ExecutableData, *api.BlobsBundleV1) error
	FullPayload() ExecutionPayload
	FullBlobsBundle() BlobsBundle
	SetValue(*big.Int)
	SetPubKey(beacon.BLSPubkey)
	SetContext(parentBlockRoot tree.Root, slot beacon.Slot, proposerIndex beacon.ValidatorIndex)
	Sign(spec *beacon.Spec, domain beacon.BLSDomain,
		sk *blsu.SecretKey,
		pk *blsu.Pubkey) (*SignedBuilderBid, error)
	ValidateReveal(publicKey *blsu.Pubkey, signedBeaconResponse SignedBeaconResponse, spec *beacon.Spec, slot beacon.Slot, genesisValidatorsRoot *tree.Root) (*UnblindedResponse, error)
	Version() string
}

type SignedBuilderBid struct {
	Message   BuilderBid          `json:"message"   yaml:"message"`
	Signature common.BLSSignature `json:"signature" yaml:"signature"`
}

func (s *SignedBuilderBid) Versioned() *VersionedSignedBuilderBid {
	return &VersionedSignedBuilderBid{
		Version: s.Message.Version(),
		Data:    s,
	}
}

type VersionedSignedBuilderBid struct {
	Version string            `json:"version" yaml:"version"`
	Data    *SignedBuilderBid `json:"data"    yaml:"data"`
}

type SignedBeaconResponse interface {
	ExecutionPayloadHash() el_common.Hash
	Root(*beacon.Spec) tree.Root
	StateRoot() tree.Root
	Slot() beacon.Slot
	ProposerIndex() beacon.ValidatorIndex
	BlockSignature() *common.BLSSignature
}

type BlindedBlobsBundle interface {
	GetCommitments() *beacon.KZGCommitments
	GetProofs() *beacon.KZGProofs
	GetBlobRoots() *deneb.BlobRoots
}

type BlobsBundle interface {
	FromAPI(*beacon.Spec, *api.BlobsBundleV1) error
	GetCommitments() *beacon.KZGCommitments
	GetProofs() *beacon.KZGProofs
	GetBlobs() *deneb.Blobs
}

type ExecutionPayload interface {
	FromExecutableData(*api.ExecutableData) error
	GetBlockHash() tree.Root
}

type UnblindedResponse struct {
	Version string      `json:"version" yaml:"version"`
	Data    interface{} `json:"data"    yaml:"data"`
}

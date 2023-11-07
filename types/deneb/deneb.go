package deneb

import (
	"bytes"
	"fmt"
	"math/big"

	api "github.com/ethereum/go-ethereum/beacon/engine"
	el_common "github.com/ethereum/go-ethereum/common"
	"github.com/marioevz/mock-builder/types/common"
	blsu "github.com/protolambda/bls12-381-util"
	beacon "github.com/protolambda/zrnt/eth2/beacon/common"
	"github.com/protolambda/zrnt/eth2/beacon/deneb"
	"github.com/protolambda/ztyp/tree"
	"github.com/protolambda/ztyp/view"
)

const Version = "deneb"

type SignedBeaconResponse deneb.SignedBlindedBeaconBlock

func (s *SignedBeaconResponse) ExecutionPayloadHash() el_common.Hash {
	var hash el_common.Hash
	copy(hash[:], s.Message.Body.ExecutionPayloadHeader.BlockHash[:])
	return hash
}

func (s *SignedBeaconResponse) Root(spec *beacon.Spec) tree.Root {
	return s.Message.HashTreeRoot(spec, tree.GetHashFn())
}

func (s *SignedBeaconResponse) StateRoot() tree.Root {
	return s.Message.StateRoot
}

func (s *SignedBeaconResponse) Slot() beacon.Slot {
	return s.Message.Slot
}

func (s *SignedBeaconResponse) ProposerIndex() beacon.ValidatorIndex {
	return s.Message.ProposerIndex
}

func (s *SignedBeaconResponse) BlockSignature() *beacon.BLSSignature {
	return &s.Signature
}

type UnblindedResponseData struct {
	ExecutionPayload *deneb.ExecutionPayload `json:"execution_payload" yaml:"execution_payload"`
	BlobsBundle      *deneb.BlobsBundle      `json:"blobs_bundle" yaml:"blobs_bundle"`
}

func (b *BuilderBid) ValidateReveal(publicKey *blsu.Pubkey, signedBeaconResponse common.SignedBeaconResponse, spec *beacon.Spec, slot beacon.Slot, genesisValidatorsRoot *tree.Root) (*common.UnblindedResponse, error) {
	sbb, ok := signedBeaconResponse.(*SignedBeaconResponse)
	if !ok {
		return nil, fmt.Errorf("invalid signed beacon response")
	}

	blockRoot := sbb.Message.HashTreeRoot(spec, tree.GetHashFn())
	s, err := sbb.Signature.Signature()
	if err != nil {
		return nil, fmt.Errorf("unable to validate block signature: %v", err)
	}

	beaconBlock, err := sbb.Message.Unblind(spec, b.Payload.ExecutionPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to unblind block: %v", err)
	}
	if beaconBlock.HashTreeRoot(spec, tree.GetHashFn()) != blockRoot {
		return nil, fmt.Errorf("unblinded block root does not match")
	}
	forkVersion := spec.ForkVersion(slot)
	if forkVersion != spec.DENEB_FORK_VERSION {
		return nil, fmt.Errorf("invalid fork version, expected 0x%x, got 0x%x", spec.DENEB_FORK_VERSION, forkVersion)
	}
	dom := beacon.ComputeDomain(beacon.DOMAIN_BEACON_PROPOSER, forkVersion, *genesisValidatorsRoot)
	signingRoot := beacon.ComputeSigningRoot(blockRoot, dom)
	if !blsu.Verify(publicKey, signingRoot[:], s) {
		return nil, fmt.Errorf("invalid block signature")
	}

	// Verify kzg commitments in signed header
	for i, kzgCommitment := range sbb.Message.Body.BlobKZGCommitments {
		if !bytes.Equal(b.BlobsBundle.KZGCommitments[i][:], kzgCommitment[:]) {
			return nil, fmt.Errorf("invalid kzg commitment")
		}
	}

	return &common.UnblindedResponse{
		Version: Version,
		Data: &UnblindedResponseData{
			ExecutionPayload: b.Payload.ExecutionPayload,
			BlobsBundle:      b.BlobsBundle.BlobsBundle,
		},
	}, nil
}

type BlobsBundle struct {
	*deneb.BlobsBundle
	Source *api.BlobsBundleV1
}

func (bb *BlobsBundle) FromAPI(spec *beacon.Spec, blobsBundle *api.BlobsBundleV1) error {
	if blobsBundle == nil {
		return fmt.Errorf("nil blobs bundle")
	}

	bb.BlobsBundle = &deneb.BlobsBundle{}

	bb.KZGCommitments = make(beacon.KZGCommitments, len(blobsBundle.Commitments))
	bb.KZGProofs = make(beacon.KZGProofs, len(blobsBundle.Proofs))
	bb.Blobs = make(deneb.Blobs, len(blobsBundle.Blobs))

	for i, blob := range blobsBundle.Blobs {
		copy(bb.KZGCommitments[i][:], blobsBundle.Commitments[i][:])
		copy(bb.KZGProofs[i][:], blobsBundle.Proofs[i][:])
		bb.Blobs[i] = make(deneb.Blob, deneb.BlobSize(spec))
		copy(bb.Blobs[i][:], blob[:])
	}

	bb.Source = blobsBundle

	return nil
}

func (bb *BlobsBundle) ToAPI() (*api.BlobsBundleV1, error) {
	if bb.Source == nil {
		return nil, fmt.Errorf("nil blobs bundle")
	}
	return bb.Source, nil
}

var _ common.BlobsBundle = (*BlobsBundle)(nil)

type BuilderBid struct {
	Payload                  *ExecutionPayload             `json:"-" yaml:"-"`
	Header                   *deneb.ExecutionPayloadHeader `json:"header" yaml:"header"`
	BlobsBundle              *BlobsBundle                  `json:"-" yaml:"-"`
	BlobKZGCommitments       *beacon.KZGCommitments        `json:"blob_kzg_commitments" yaml:"blob_kzg_commitments"`
	Value                    view.Uint256View              `json:"value"  yaml:"value"`
	PubKey                   beacon.BLSPubkey              `json:"pubkey" yaml:"pubkey"`
	common.BuilderBidContext `json:"-" yaml:"-"`
}

var _ common.BuilderBid = (*BuilderBid)(nil)

func (b *BuilderBid) Version() string {
	return Version
}

func (b *BuilderBid) HashTreeRoot(spec *beacon.Spec, hFn tree.HashFn) tree.Root {
	return hFn.HashTreeRoot(
		b.Header,
		spec.Wrap(b.BlobKZGCommitments),
		&b.Value,
		&b.PubKey,
	)
}

func (b *BuilderBid) Build(
	spec *beacon.Spec,
	ed *api.ExecutableData,
	bb *api.BlobsBundleV1,
	parentBlockRoot tree.Root,
	slot beacon.Slot,
	proposerIndex beacon.ValidatorIndex,
) error {
	if ed == nil {
		return fmt.Errorf("nil execution payload")
	}

	b.Payload = new(ExecutionPayload)
	err := b.Payload.FromExecutableData(ed, &parentBlockRoot)
	if err != nil {
		return err
	}

	b.Header = b.Payload.Header(spec)

	if bb == nil {
		return fmt.Errorf("nil blobs bundle")
	}

	b.BlobsBundle = new(BlobsBundle)
	if err := b.BlobsBundle.FromAPI(spec, bb); err != nil {
		return err
	}

	b.BlobKZGCommitments = &b.BlobsBundle.KZGCommitments

	b.ParentBlockRoot = parentBlockRoot
	b.Slot = slot
	b.ProposerIndex = proposerIndex

	return nil
}

func (b *BuilderBid) FullPayload() common.ExecutionPayload {
	return b.Payload
}

func (b *BuilderBid) FullBlobsBundle() common.BlobsBundle {
	return b.BlobsBundle
}

func (b *BuilderBid) SetValue(value *big.Int) {
	b.Value.SetFromBig(value)
}

func (b *BuilderBid) SetPubKey(pk beacon.BLSPubkey) {
	b.PubKey = pk
}

func (b *BuilderBid) Sign(
	spec *beacon.Spec,
	domain beacon.BLSDomain,
	sk *blsu.SecretKey,
	pk *blsu.Pubkey,
) (*common.SignedBuilderBid, error) {
	pkBytes := pk.Serialize()
	copy(b.PubKey[:], pkBytes[:])
	sigRoot := beacon.ComputeSigningRoot(
		b.HashTreeRoot(spec, tree.GetHashFn()),
		domain,
	)
	return &common.SignedBuilderBid{
		Message:   b,
		Signature: beacon.BLSSignature(blsu.Sign(sk, sigRoot[:]).Serialize()),
	}, nil
}

type ExecutionPayload struct {
	*deneb.ExecutionPayload
	Source     *api.ExecutableData
	BeaconRoot *tree.Root
}

func (p *ExecutionPayload) FromExecutableData(ed *api.ExecutableData, beaconRoot *tree.Root) error {
	if ed == nil {
		return fmt.Errorf("nil execution payload")
	}
	if ed.Withdrawals == nil {
		return fmt.Errorf("execution data does not contain withdrawals")
	}
	if ed.BlobGasUsed == nil {
		return fmt.Errorf("execution data does not contain blob gas used")
	}
	if ed.ExcessBlobGas == nil {
		return fmt.Errorf("execution data does not contain excess blob gas")
	}

	p.ExecutionPayload = &deneb.ExecutionPayload{}
	copy(p.ParentHash[:], ed.ParentHash[:])
	copy(p.FeeRecipient[:], ed.FeeRecipient[:])
	copy(p.StateRoot[:], ed.StateRoot[:])
	copy(p.ReceiptsRoot[:], ed.ReceiptsRoot[:])
	copy(p.LogsBloom[:], ed.LogsBloom[:])
	copy(p.PrevRandao[:], ed.Random[:])

	p.BlockNumber = view.Uint64View(ed.Number)
	p.GasLimit = view.Uint64View(ed.GasLimit)
	p.GasUsed = view.Uint64View(ed.GasUsed)
	p.Timestamp = beacon.Timestamp(ed.Timestamp)

	p.ExtraData = make(beacon.ExtraData, len(ed.ExtraData))
	copy(p.ExtraData[:], ed.ExtraData[:])
	p.BaseFeePerGas.SetFromBig(ed.BaseFeePerGas)
	copy(p.BlockHash[:], ed.BlockHash[:])
	p.Transactions = make(beacon.PayloadTransactions, len(ed.Transactions))
	for i, tx := range ed.Transactions {
		p.Transactions[i] = make(beacon.Transaction, len(tx))
		copy(p.Transactions[i][:], tx[:])
	}
	p.Withdrawals = make(beacon.Withdrawals, len(ed.Withdrawals))
	for i, w := range ed.Withdrawals {
		p.Withdrawals[i].Index = beacon.WithdrawalIndex(w.Index)
		p.Withdrawals[i].ValidatorIndex = beacon.ValidatorIndex(w.Validator)
		copy(p.Withdrawals[i].Address[:], w.Address[:])
		p.Withdrawals[i].Amount = beacon.Gwei(w.Amount)
	}
	p.BlobGasUsed = view.Uint64View(*ed.BlobGasUsed)
	p.ExcessBlobGas = view.Uint64View(*ed.ExcessBlobGas)
	p.BeaconRoot = beaconRoot
	p.Source = ed
	return nil
}

func (p *ExecutionPayload) ToExecutableData() (*api.ExecutableData, *el_common.Hash, error) {
	if p.Source == nil {
		return nil, nil, fmt.Errorf("nil execution payload")
	}
	var beaconRoot el_common.Hash
	copy(beaconRoot[:], p.BeaconRoot[:])
	return p.Source, &beaconRoot, nil
}

func (p *ExecutionPayload) GetBlockHash() tree.Root {
	if p == nil {
		panic("nil execution payload")
	}
	return p.BlockHash
}

var _ common.ExecutionPayload = (*ExecutionPayload)(nil)

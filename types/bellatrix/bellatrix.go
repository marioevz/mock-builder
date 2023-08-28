package bellatrix

import (
	"fmt"
	"math/big"

	api "github.com/ethereum/go-ethereum/beacon/engine"
	el_common "github.com/ethereum/go-ethereum/common"
	"github.com/marioevz/mock-builder/types/common"
	blsu "github.com/protolambda/bls12-381-util"
	"github.com/protolambda/zrnt/eth2/beacon/bellatrix"
	beacon "github.com/protolambda/zrnt/eth2/beacon/common"
	"github.com/protolambda/ztyp/tree"
	"github.com/protolambda/ztyp/view"
)

const Version = "bellatrix"

type SignedBeaconResponse bellatrix.SignedBlindedBeaconBlock

var _ = common.SignedBeaconResponse((*SignedBeaconResponse)(nil))

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

type BuilderBid struct {
	Payload                  *ExecutionPayload                 `json:"-" yaml:"-"`
	Header                   *bellatrix.ExecutionPayloadHeader `json:"header" yaml:"header"`
	Value                    view.Uint256View                  `json:"value"  yaml:"value"`
	PubKey                   beacon.BLSPubkey                  `json:"pubkey" yaml:"pubkey"`
	common.BuilderBidContext `json:"-" yaml:"-"`
}

var _ common.BuilderBid = (*BuilderBid)(nil)

func (b *BuilderBid) Version() string {
	return Version
}

func (b *BuilderBid) HashTreeRoot(hFn tree.HashFn) tree.Root {
	return hFn.HashTreeRoot(
		b.Header,
		&b.Value,
		&b.PubKey,
	)
}

func (b *BuilderBid) Build(
	spec *beacon.Spec,
	ed *api.ExecutableData,
	_ *api.BlobsBundleV1,
	parentBlockRoot tree.Root,
	slot beacon.Slot,
	proposerIndex beacon.ValidatorIndex,
) error {
	if ed == nil {
		return fmt.Errorf("nil execution payload")
	}
	b.Payload = new(ExecutionPayload)
	if err := b.Payload.FromExecutableData(ed, nil); err != nil {
		return err
	}

	b.Header = b.Payload.Header(spec)
	b.ParentBlockRoot = parentBlockRoot
	b.Slot = slot
	b.ProposerIndex = proposerIndex
	return nil
}

func (b *BuilderBid) ValidateReveal(publicKey *blsu.Pubkey, signedBeaconResponse common.SignedBeaconResponse, spec *beacon.Spec, slot beacon.Slot, genesisValidatorsRoot *tree.Root) (*common.UnblindedResponse, error) {

	sbb, ok := signedBeaconResponse.(*SignedBeaconResponse)
	if !ok {
		return nil, fmt.Errorf("invalid signed beacon response")
	}

	// Unblind and compare roots
	root := sbb.Root(spec)
	beaconBlock, err := sbb.Message.Unblind(spec, b.Payload.ExecutionPayload)
	if err != nil {
		return nil, fmt.Errorf("failed to unblind block: %v", err)
	}
	if beaconBlock.HashTreeRoot(spec, tree.GetHashFn()) != root {
		return nil, fmt.Errorf("unblinded block root does not match")
	}

	s, err := sbb.Signature.Signature()
	if err != nil {
		return nil, fmt.Errorf("unable to validate signature: %v", err)
	}

	dom := beacon.ComputeDomain(beacon.DOMAIN_BEACON_PROPOSER, spec.ForkVersion(slot), *genesisValidatorsRoot)
	signingRoot := beacon.ComputeSigningRoot(root, dom)
	if !blsu.Verify(publicKey, signingRoot[:], s) {
		return nil, fmt.Errorf("invalid signature")
	}

	return &common.UnblindedResponse{
		Version: Version,
		Data:    b.Payload,
	}, nil
}

func (sbb *SignedBeaconResponse) Validate(pk *blsu.Pubkey, spec *beacon.Spec, slot beacon.Slot, genesisValidatorsRoot *tree.Root, ep common.ExecutionPayload, bb common.BlobsBundle) error {

	return nil
}

func (b *BuilderBid) FullPayload() common.ExecutionPayload {
	return b.Payload
}

func (b *BuilderBid) FullBlobsBundle() common.BlobsBundle {
	return nil
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
		b.HashTreeRoot(tree.GetHashFn()),
		domain,
	)
	return &common.SignedBuilderBid{
		Message:   b,
		Signature: beacon.BLSSignature(blsu.Sign(sk, sigRoot[:]).Serialize()),
	}, nil
}

type ExecutionPayload struct {
	*bellatrix.ExecutionPayload
	Source *api.ExecutableData
}

func (p *ExecutionPayload) FromExecutableData(ed *api.ExecutableData, _ *tree.Root) error {
	if ed == nil {
		return fmt.Errorf("nil execution payload")
	}
	if ed.Withdrawals != nil {
		return fmt.Errorf("execution data contains withdrawals")
	}
	p.ExecutionPayload = &bellatrix.ExecutionPayload{}
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
	p.Source = ed
	return nil
}

func (p *ExecutionPayload) ToExecutableData() (*api.ExecutableData, *el_common.Hash, error) {
	if p.Source == nil {
		return nil, nil, fmt.Errorf("nil execution payload")
	}
	return p.Source, nil, nil
}

func (p *ExecutionPayload) GetBlockHash() tree.Root {
	if p.ExecutionPayload == nil {
		panic("nil execution payload")
	}
	return p.BlockHash
}

var _ common.ExecutionPayload = (*ExecutionPayload)(nil)

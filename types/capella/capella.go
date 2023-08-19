package capella

import (
	"fmt"
	"math/big"

	api "github.com/ethereum/go-ethereum/beacon/engine"
	el_common "github.com/ethereum/go-ethereum/common"
	"github.com/marioevz/mock-builder/types/common"
	blsu "github.com/protolambda/bls12-381-util"
	"github.com/protolambda/zrnt/eth2/beacon/capella"
	beacon "github.com/protolambda/zrnt/eth2/beacon/common"
	"github.com/protolambda/ztyp/tree"
	"github.com/protolambda/ztyp/view"
)

type SignedBeaconBlock capella.SignedBeaconBlock

func (s *SignedBeaconBlock) ExecutionPayloadHash() el_common.Hash {
	var hash el_common.Hash
	copy(hash[:], s.Message.Body.ExecutionPayload.BlockHash[:])
	return hash
}

func (s *SignedBeaconBlock) Root(spec *beacon.Spec) tree.Root {
	return s.Message.HashTreeRoot(spec, tree.GetHashFn())
}

func (s *SignedBeaconBlock) StateRoot() tree.Root {
	return s.Message.StateRoot
}

func (s *SignedBeaconBlock) Slot() beacon.Slot {
	return s.Message.Slot
}

func (s *SignedBeaconBlock) ProposerIndex() beacon.ValidatorIndex {
	return s.Message.ProposerIndex
}

func (s *SignedBeaconBlock) BlockSignature() *beacon.BLSSignature {
	return &s.Signature
}

func (s *SignedBeaconBlock) Reveal(
	ep common.ExecutionPayload,
	bb common.BlobsBundle,
) error {
	if bb != nil {
		return fmt.Errorf("execution data contains blobs")
	}
	if ep, ok := ep.(common.ExecutionPayloadCapella); ok {
		s.Message.Body.ExecutionPayload.ParentHash = ep.GetParentHash()
		s.Message.Body.ExecutionPayload.FeeRecipient = ep.GetFeeRecipient()
		s.Message.Body.ExecutionPayload.StateRoot = ep.GetStateRoot()
		s.Message.Body.ExecutionPayload.ReceiptsRoot = ep.GetReceiptsRoot()
		s.Message.Body.ExecutionPayload.LogsBloom = ep.GetLogsBloom()
		s.Message.Body.ExecutionPayload.PrevRandao = ep.GetPrevRandao()
		s.Message.Body.ExecutionPayload.BlockNumber = ep.GetBlockNumber()
		s.Message.Body.ExecutionPayload.GasLimit = ep.GetGasLimit()
		s.Message.Body.ExecutionPayload.GasUsed = ep.GetGasUsed()
		s.Message.Body.ExecutionPayload.Timestamp = ep.GetTimestamp()
		s.Message.Body.ExecutionPayload.ExtraData = ep.GetExtraData()
		s.Message.Body.ExecutionPayload.BaseFeePerGas = ep.GetBaseFeePerGas()
		s.Message.Body.ExecutionPayload.BlockHash = ep.GetBlockHash()
		s.Message.Body.ExecutionPayload.Transactions = ep.GetTransactions()
		s.Message.Body.ExecutionPayload.Withdrawals = ep.GetWithdrawals()
		return nil
	} else {
		return fmt.Errorf("invalid payload for capella")
	}
}

func (sbb *SignedBeaconBlock) Validate(pk *blsu.Pubkey, spec *beacon.Spec, genesisValidatorsRoot *tree.Root) error {
	root := sbb.Root(spec)
	sig := sbb.BlockSignature()
	s, err := sig.Signature()
	if err != nil {
		return fmt.Errorf("unable to validate signature: %v", err)
	}

	dom := beacon.ComputeDomain(beacon.DOMAIN_BEACON_PROPOSER, spec.ForkVersion(sbb.Slot()), *genesisValidatorsRoot)
	signingRoot := beacon.ComputeSigningRoot(root, dom)
	if !blsu.Verify(pk, signingRoot[:], s) {
		return fmt.Errorf("invalid signature")
	}

	return nil
}

type BuilderBid struct {
	Header capella.ExecutionPayloadHeader `json:"header" yaml:"header"`
	Value  view.Uint256View               `json:"value"  yaml:"value"`
	PubKey beacon.BLSPubkey               `json:"pubkey" yaml:"pubkey"`
}

func (b *BuilderBid) HashTreeRoot(hFn tree.HashFn) tree.Root {
	return hFn.HashTreeRoot(
		&b.Header,
		&b.Value,
		&b.PubKey,
	)
}

func (b *BuilderBid) Build(
	spec *beacon.Spec,
	ed *api.ExecutableData,
	_ common.BlobsBundle,
) error {
	if ed == nil {
		return fmt.Errorf("nil execution payload")
	}
	if ed.Withdrawals == nil {
		return fmt.Errorf("execution data does not contain withdrawals")
	}
	copy(b.Header.ParentHash[:], ed.ParentHash[:])
	copy(b.Header.FeeRecipient[:], ed.FeeRecipient[:])
	copy(b.Header.StateRoot[:], ed.StateRoot[:])
	copy(b.Header.ReceiptsRoot[:], ed.ReceiptsRoot[:])
	copy(b.Header.LogsBloom[:], ed.LogsBloom[:])
	copy(b.Header.PrevRandao[:], ed.Random[:])

	b.Header.BlockNumber = view.Uint64View(ed.Number)
	b.Header.GasLimit = view.Uint64View(ed.GasLimit)
	b.Header.GasUsed = view.Uint64View(ed.GasUsed)
	b.Header.Timestamp = beacon.Timestamp(ed.Timestamp)

	b.Header.ExtraData = make(beacon.ExtraData, len(ed.ExtraData))
	copy(b.Header.ExtraData[:], ed.ExtraData[:])
	b.Header.BaseFeePerGas.SetFromBig(ed.BaseFeePerGas)
	copy(b.Header.BlockHash[:], ed.BlockHash[:])

	txs := make(beacon.PayloadTransactions, len(ed.Transactions))
	for i, tx := range ed.Transactions {
		txs[i] = make(beacon.Transaction, len(tx))
		copy(txs[i][:], tx[:])
	}
	txRoot := txs.HashTreeRoot(spec, tree.GetHashFn())
	copy(b.Header.TransactionsRoot[:], txRoot[:])

	withdrawals := make(beacon.Withdrawals, len(ed.Withdrawals))
	for i, w := range ed.Withdrawals {
		withdrawals[i].Index = beacon.WithdrawalIndex(w.Index)
		withdrawals[i].ValidatorIndex = beacon.ValidatorIndex(w.Validator)
		copy(withdrawals[i].Address[:], w.Address[:])
		withdrawals[i].Amount = beacon.Gwei(w.Amount)
	}
	withdrawalsRoot := withdrawals.HashTreeRoot(spec, tree.GetHashFn())
	copy(b.Header.WithdrawalsRoot[:], withdrawalsRoot[:])

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

type ExecutionPayload capella.ExecutionPayload

func (p *ExecutionPayload) FromExecutableData(ed *api.ExecutableData) error {
	if ed == nil {
		return fmt.Errorf("nil execution payload")
	}
	if ed.Withdrawals == nil {
		return fmt.Errorf("execution data does not contain withdrawals")
	}
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
	return nil
}

func (p *ExecutionPayload) GetParentHash() beacon.Hash32 {
	return p.ParentHash
}

func (p *ExecutionPayload) GetFeeRecipient() beacon.Eth1Address {
	return p.FeeRecipient
}

func (p *ExecutionPayload) GetStateRoot() beacon.Bytes32 {
	return p.StateRoot
}

func (p *ExecutionPayload) GetReceiptsRoot() beacon.Bytes32 {
	return p.ReceiptsRoot
}

func (p *ExecutionPayload) GetLogsBloom() beacon.LogsBloom {
	return p.LogsBloom
}

func (p *ExecutionPayload) GetPrevRandao() beacon.Bytes32 {
	return p.PrevRandao
}

func (p *ExecutionPayload) GetBlockNumber() view.Uint64View {
	return p.BlockNumber
}

func (p *ExecutionPayload) GetGasLimit() view.Uint64View {
	return p.GasLimit
}

func (p *ExecutionPayload) GetGasUsed() view.Uint64View {
	return p.GasUsed
}

func (p *ExecutionPayload) GetTimestamp() beacon.Timestamp {
	return p.Timestamp
}

func (p *ExecutionPayload) GetExtraData() beacon.ExtraData {
	return p.ExtraData
}

func (p *ExecutionPayload) GetBaseFeePerGas() view.Uint256View {
	return p.BaseFeePerGas
}

func (p *ExecutionPayload) GetBlockHash() beacon.Hash32 {
	return p.BlockHash
}

func (p *ExecutionPayload) GetTransactions() beacon.PayloadTransactions {
	return p.Transactions
}

func (p *ExecutionPayload) GetWithdrawals() beacon.Withdrawals {
	return p.Withdrawals
}

var _ common.ExecutionPayloadCapella = (*ExecutionPayload)(nil)

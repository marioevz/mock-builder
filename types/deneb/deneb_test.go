package deneb

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"testing"

	api "github.com/ethereum/go-ethereum/beacon/engine"
	el_common "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/protolambda/zrnt/eth2/beacon/common"
	"github.com/protolambda/zrnt/eth2/beacon/deneb"
	"github.com/protolambda/zrnt/eth2/configs"
	"github.com/protolambda/ztyp/tree"
)

func pUint64(i uint64) *uint64 {
	return &i
}

func TestDenebBidBuilding(t *testing.T) {
	spec := configs.Mainnet
	bid := &BuilderBid{}

	ed := &api.ExecutableData{
		BaseFeePerGas: new(big.Int),
		Withdrawals:   types.Withdrawals{},
		BlobGasUsed:   pUint64(0),
		ExcessBlobGas: pUint64(0),
	}
	commitments := []hexutil.Bytes{
		make(hexutil.Bytes, common.KZGCommitmentSize),
	}
	proofs := []hexutil.Bytes{
		make(hexutil.Bytes, common.KZGCommitmentSize),
	}
	blobs := []hexutil.Bytes{
		make(hexutil.Bytes, deneb.BlobSize(spec)),
	}
	bb := &api.BlobsBundleV1{
		Commitments: commitments,
		Proofs:      proofs,
		Blobs:       blobs,
	}

	err := bid.Build(
		spec,
		ed,
		bb,
		tree.Root{},
		0,
		0,
	)
	if err != nil {
		t.Fatal(err)
	}

	if bid.Payload == nil {
		t.Fatal("payload not built")
	}

	if bid.Header == nil {
		t.Fatal("header not built")
	}

	if bid.BlobKZGCommitments == nil {
		t.Fatal("blob kzg commitments empty")
	}

	if bid.BlobsBundle == nil {
		t.Fatal("blobs bundle not built")
	}

	for i, blob := range bid.BlobsBundle.Blobs {
		if blob == nil {
			t.Fatalf("nil blob %d", i)
		}
		if len(blob) != int(deneb.BlobSize(spec)) {
			t.Fatalf("invalid blob size %d", i)
		}
	}

	for i, blobKzg := range *bid.BlobKZGCommitments {
		if !bytes.Equal(blobKzg[:], bid.BlobsBundle.KZGCommitments[i][:]) {
			t.Fatalf("blob kzg commitment %d not set", i)
		}
	}
}

func TestBidHashTreeRoot(t *testing.T) {
	for i, tc := range []struct {
		jsonBid     string
		expectedHTR string
	}{
		{
			jsonBid: `{
				"header": {
				  "parent_hash": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
				  "fee_recipient": "0xabcf8e0d4e9587369b2301d0790347320302cc09",
				  "state_root": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
				  "receipts_root": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
				  "logs_bloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
				  "prev_randao": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
				  "block_number": "1",
				  "gas_limit": "1",
				  "gas_used": "1",
				  "timestamp": "1",
				  "extra_data": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
				  "base_fee_per_gas": "1",
				  "blob_gas_used": "1",
				  "excess_blob_gas": "1",
				  "block_hash": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
				  "transactions_root": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2",
				  "withdrawals_root": "0xcf8e0d4e9587369b2301d0790347320302cc0943d5a1884560367e8208d920f2"
				},
				"blob_kzg_commitments": [
				  "0xa94170080872584e54a1cf092d845703b13907f2e6b3b1c0ad573b910530499e3bcd48c6378846b80d2bfa58c81cf3d5"
				],
				"value": "1",
				"pubkey": "0x93247f2209abcacf57b75a51dafae777f9dd38bc7053d1af526f220a7489a6d3a2753e5f3e8b1cfe39b56f43611df74a"
			  }`,
			expectedHTR: "0xb8badff2ce16663a6a3100943d008c6a64d996ca6f7b4310a4c690015b3fb587",
		},
	} {
		t.Run(fmt.Sprintf("htr-%d", i), func(t *testing.T) {
			builderBid := BuilderBid{}
			err := json.Unmarshal([]byte(tc.jsonBid), &builderBid)
			if err != nil {
				t.Errorf("failed to unmarshal json: %v", err)
			}
			bidHash := builderBid.HashTreeRoot(configs.Mainnet, tree.GetHashFn())
			expectedHTR := el_common.HexToHash(tc.expectedHTR)
			if !bytes.Equal(bidHash[:], expectedHTR[:]) {
				t.Errorf("expected hash %s, got %s", expectedHTR, bidHash)
			}
		})
	}
}

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

	if bid.BlindedBlobsBundle == nil {
		t.Fatal("blinded blobs bundle not built")
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

	if len(bid.BlindedBlobsBundle.BlobRoots) != len(bid.BlobsBundle.Blobs) {
		t.Fatal("invalid blinded blobs bundle")
	}

	for i, blobRoot := range bid.BlindedBlobsBundle.BlobRoots {
		calcRoot := bid.BlobsBundle.Blobs[i].HashTreeRoot(spec, tree.GetHashFn())
		fmt.Printf("blob root %d: %s\n", i, calcRoot)
		if !bytes.Equal(blobRoot[:], calcRoot[:]) {
			t.Fatalf("hash tree root mismatch on root %d", i)
		}
		// Check also if the root is not zero
		if blobRoot == tree.Root([32]byte{}) {
			t.Fatalf("zero hash tree root mismatch on root %d: %s", i, blobRoot)
		}
	}
}

func TestBidHashTreeRoot(t *testing.T) {
	for i, tc := range []struct {
		jsonBid      string
		expectedHash string
	}{
		{
			jsonBid: `{
				"header": {
					"parent_hash": "0x190caa185cdeb86d0a7472e6447a92a39b762f4ea696d3d19d47bba4eb7fa935",
					"fee_recipient": "0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b",
					"state_root": "0x2affac6b1bdc0a25fea0175fa6be328ebb16f880f0f1fdf458bd7bf19842fa60",
					"receipts_root": "0x7aca796fcc5d37e5c8dd6705e01b315fa28619159a1347cd14aabef1d52ff035",
					"logs_bloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
					"prev_randao": "0xd361841f2f8648166b502b92bded23fcaf0610cc41705e2d64e7450500743511",
					"block_number": "35",
					"gas_limit": "30000000",
					"gas_used": "840000",
					"timestamp": "1693427860",
					"extra_data": "0x6275696c646572207061796c6f616420747374",
					"base_fee_per_gas": "11703946",
					"block_hash": "0x8ed0f7bc908d61f7e453d3dc5ffc52694a3e584cc9119b63f12a30f193b068bf",
					"transactions_root": "0x58ebe57ba95bd5d191bd94a8612be571f5b26e83dd2314c20caad3ddbb69799d",
					"withdrawals_root": "0x792930bbd5baac43bcc798ee49aa8185ef76bb3b44ba62b91d86ae569e4bb535",
					"blob_gas_used": "0",
					"excess_blob_gas": "0"
				},
				"blinded_blobs_bundle": {
					"commitments": [],
					"proofs": [],
					"blob_roots": []
				},
				"value": "8400000000000000",
				"pubkey": "0x95fde78acd5f6886ddaf5d0056610167c513d09c1c0efabbc7cdcc69beea113779c4a81e2d24daafc5387dbf6ac5fe48"
			}`,
			expectedHash: "0xfdc1374279c7f4ac309ded5f9e028f60f07eafdb012f835f1ef4969a76e750c4",
		},
	} {
		t.Run(fmt.Sprintf("htr-%d", i), func(t *testing.T) {
			builderBid := BuilderBid{}
			err := json.Unmarshal([]byte(tc.jsonBid), &builderBid)
			if err != nil {
				t.Errorf("failed to unmarshal json: %v", err)
			}
			bidHash := builderBid.HashTreeRoot(configs.Mainnet, tree.GetHashFn())
			expectedHash := el_common.HexToHash(tc.expectedHash)
			if !bytes.Equal(bidHash[:], expectedHash[:]) {
				t.Errorf("expected hash %s, got %s", expectedHash, bidHash)
			}
		})
	}
}

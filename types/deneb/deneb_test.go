package deneb

import (
	"bytes"
	"fmt"
	"math/big"
	"testing"

	api "github.com/ethereum/go-ethereum/beacon/engine"
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

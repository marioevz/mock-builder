package capella

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/protolambda/zrnt/eth2/configs"
	"github.com/protolambda/ztyp/tree"
)

func TestBidHashTreeRoot(t *testing.T) {
	for i, tc := range []struct {
		jsonBid      string
		expectedHash string
	}{
		{
			jsonBid: `{
				"header": {
					"parent_hash": "0x83202a6c38663aae8698bb2fcef13fb90f5c7f0e1c3c78c79868b9ca7e1447ff",
					"fee_recipient": "0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b",
					"state_root": "0x3b837390c27eb0e942f244bcd26846eedb1d700b92b0e5b281865a38b4d23215",
					"receipts_root": "0x022ef61f2ebf0a152c0a9666f125bf7c136d381030d53b39afbebbcd52474f79",
					"logs_bloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
					"prev_randao": "0x56dfb907db624dd0ac4d33fae369903fb503a514dc80f62930d8fababf710211",
					"block_number": "3",
					"gas_limit": "30000000",
					"gas_used": "630000",
					"timestamp": "1693427668",
					"extra_data": "0x6275696c646572207061796c6f616420747374",
					"base_fee_per_gas": "694708985",
					"block_hash": "0x64abe51201d17632c49451cc56234e5302e4c8accc78f0f505adca2a7a641d5b",
					"transactions_root": "0xf98871e64d8f973e98ea046d7f10bdb3dee2381f0d4640beda219ec73feba2d1",
					"withdrawals_root": "0x792930bbd5baac43bcc798ee49aa8185ef76bb3b44ba62b91d86ae569e4bb535"
				},
				"value": "6300000000000000",
				"pubkey": "0x95fde78acd5f6886ddaf5d0056610167c513d09c1c0efabbc7cdcc69beea113779c4a81e2d24daafc5387dbf6ac5fe48"
			}`,
			expectedHash: "0xda93b875bc2f2d729b77cb65849cb1cb7aa9bdb93957a1592dc5a0f8ff78831e",
		},
	} {
		t.Run(fmt.Sprintf("htr-%d", i), func(t *testing.T) {
			builderBid := BuilderBid{}
			err := json.Unmarshal([]byte(tc.jsonBid), &builderBid)
			if err != nil {
				t.Errorf("failed to unmarshal json: %v", err)
			}
			bidHash := builderBid.HashTreeRoot(configs.Mainnet, tree.GetHashFn())
			expectedHash := common.HexToHash(tc.expectedHash)
			if !bytes.Equal(bidHash[:], expectedHash[:]) {
				t.Errorf("expected hash %s, got %s", expectedHash, bidHash)
			}
		})
	}
}

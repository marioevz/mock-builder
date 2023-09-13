package builder_types

import (
	"github.com/marioevz/mock-builder/types/common"
	beacon "github.com/protolambda/zrnt/eth2/beacon/common"
)

type Builder interface {
	Address() string
	Cancel() error
	GetBuiltPayloadsCount() int
	GetSignedBeaconBlockCount() int
	GetSignedBeaconBlocks() map[beacon.Slot]common.SignedBeaconResponse
	GetModifiedPayloads() map[beacon.Slot]common.ExecutionPayload
	GetBuiltPayloads() map[beacon.Slot]common.BuilderBid
}

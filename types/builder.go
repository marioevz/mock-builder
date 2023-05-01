package builder_types

import (
	api "github.com/ethereum/go-ethereum/beacon/engine"
	"github.com/marioevz/mock-builder/types/common"
	beacon "github.com/protolambda/zrnt/eth2/beacon/common"
)

type Builder interface {
	Address() string
	Cancel() error
	GetBuiltPayloadsCount() int
	GetSignedBeaconBlockCount() int
	GetSignedBeaconBlocks() map[beacon.Slot]common.SignedBeaconBlock
	GetModifiedPayloads() map[beacon.Slot]*api.ExecutableData
	GetBuiltPayloads() map[beacon.Slot]*api.ExecutableData
}

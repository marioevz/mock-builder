package mock_builder

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"sync"

	api "github.com/ethereum/go-ethereum/beacon/engine"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/marioevz/mock-builder/types/bellatrix"
	"github.com/marioevz/mock-builder/types/common"
	beacon "github.com/protolambda/zrnt/eth2/beacon/common"
)

type PayloadAttributesModifier func(*api.PayloadAttributes, beacon.Slot) (bool, error)
type PayloadModifier func(*api.ExecutableData, beacon.Slot) (bool, error)
type ErrorProducer func(beacon.Slot) error
type PayloadWeiBidModifier func(*big.Int) (*big.Int, error)
type GetBuilderBidVersion func(beacon.Slot) (common.BuilderBid, string, error)

type config struct {
	id                      int
	port                    int
	host                    string
	extraDataWatermark      string
	spec                    *beacon.Spec
	externalIP              net.IP
	beaconGenesisTime       beacon.Timestamp
	payloadWeiValueModifier PayloadWeiBidModifier

	payloadAttrModifier  PayloadAttributesModifier
	payloadModifier      PayloadModifier
	errorOnHeaderRequest ErrorProducer
	errorOnPayloadReveal ErrorProducer

	builderBidVersionResolver GetBuilderBidVersion

	mutex sync.Mutex
}
type Option struct {
	apply       func(m *MockBuilder) error
	description string
}

func (o Option) MarshalText() ([]byte, error) {
	return []byte(o.description), nil
}

func WithID(id int) Option {
	return Option{
		apply: func(m *MockBuilder) error {
			m.cfg.mutex.Lock()
			defer m.cfg.mutex.Unlock()
			m.cfg.id = id
			return nil
		},
		description: fmt.Sprintf("WithID(%d)", id),
	}
}

func WithHost(host string) Option {
	return Option{
		apply: func(m *MockBuilder) error {
			m.cfg.mutex.Lock()
			defer m.cfg.mutex.Unlock()
			m.cfg.host = host
			return nil
		},
		description: fmt.Sprintf("WithHost(%s)", host),
	}
}

func WithPort(port int) Option {
	return Option{
		apply: func(m *MockBuilder) error {
			m.cfg.mutex.Lock()
			defer m.cfg.mutex.Unlock()
			m.cfg.port = port
			return nil
		},
		description: fmt.Sprintf("WithPort(%d)", port),
	}
}

func WithExtraDataWatermark(wm string) Option {
	return Option{
		apply: func(m *MockBuilder) error {
			m.cfg.mutex.Lock()
			defer m.cfg.mutex.Unlock()
			m.cfg.extraDataWatermark = wm
			return nil
		},
		description: fmt.Sprintf("WithExtraDataWatermark(%s)", wm),
	}
}

func WithExternalIP(ip net.IP) Option {
	return Option{
		apply: func(m *MockBuilder) error {
			m.cfg.mutex.Lock()
			defer m.cfg.mutex.Unlock()
			m.cfg.externalIP = ip
			return nil
		},
		description: fmt.Sprintf("WithExternalIP(%s)", ip),
	}
}

func WithSpec(spec *beacon.Spec) Option {
	return Option{
		apply: func(m *MockBuilder) error {
			m.cfg.mutex.Lock()
			defer m.cfg.mutex.Unlock()
			m.cfg.spec = spec
			return nil
		},
		description: "WithSpec", // TODO: actually format the spec
	}
}

func WithBeaconGenesisTime(t beacon.Timestamp) Option {
	return Option{
		apply: func(m *MockBuilder) error {
			m.cfg.mutex.Lock()
			defer m.cfg.mutex.Unlock()
			m.cfg.beaconGenesisTime = t
			return nil
		},
		description: fmt.Sprintf("WithBeaconGenesisTime(%d)", t),
	}
}

func WithPayloadWeiValueBump(bump *big.Int) Option {
	return Option{
		apply: func(m *MockBuilder) error {
			m.cfg.mutex.Lock()
			defer m.cfg.mutex.Unlock()
			m.cfg.payloadWeiValueModifier = func(orig *big.Int) (*big.Int, error) {
				ret := new(big.Int).Set(orig)
				ret.Add(ret, bump)
				return ret, nil
			}
			return nil
		},
		description: fmt.Sprintf("WithPayloadWeiValueBump(%d)", bump),
	}
}

func WithPayloadWeiValueMultiplier(mult *big.Int) Option {
	return Option{
		apply: func(m *MockBuilder) error {
			m.cfg.mutex.Lock()
			defer m.cfg.mutex.Unlock()
			m.cfg.payloadWeiValueModifier = func(orig *big.Int) (*big.Int, error) {
				ret := new(big.Int).Set(orig)
				ret.Mul(ret, mult)
				return ret, nil
			}
			return nil
		},
		description: fmt.Sprintf("WithPayloadWeiValueMultiplier(%d)", mult),
	}
}

func WithPayloadAttributesModifier(pam PayloadAttributesModifier) Option {
	return Option{
		apply: func(m *MockBuilder) error {
			m.cfg.mutex.Lock()
			defer m.cfg.mutex.Unlock()
			m.cfg.payloadAttrModifier = pam
			return nil
		},
		description: "WithPayloadAttributesModifier",
	}
}

func WithPayloadModifier(pm PayloadModifier) Option {
	return Option{
		apply: func(m *MockBuilder) error {
			m.cfg.mutex.Lock()
			defer m.cfg.mutex.Unlock()
			m.cfg.payloadModifier = pm
			return nil
		},
		description: "WithPayloadModifier",
	}
}

func WithErrorOnHeaderRequest(e ErrorProducer) Option {
	return Option{
		apply: func(m *MockBuilder) error {
			m.cfg.mutex.Lock()
			defer m.cfg.mutex.Unlock()
			m.cfg.errorOnHeaderRequest = e
			return nil
		},
		description: "WithErrorOnHeaderRequest",
	}
}

func WithErrorOnHeaderRequestAtEpoch(epoch beacon.Epoch) Option {
	return Option{
		apply: func(m *MockBuilder) error {
			m.cfg.mutex.Lock()
			defer m.cfg.mutex.Unlock()

			var spec = m.cfg.spec
			if spec == nil {
				return fmt.Errorf("unknown spec")
			}
			startSlot, err := spec.EpochStartSlot(epoch)
			if err != nil {
				return err
			}

			m.cfg.errorOnHeaderRequest = func(s beacon.Slot) error {
				if s >= startSlot {
					return fmt.Errorf("error generator")
				}

				return nil
			}
			return nil
		},
		description: fmt.Sprintf("WithErrorOnHeaderRequestAtEpoch(%d)", epoch),
	}
}

func WithErrorOnHeaderRequestAtSlot(slot beacon.Slot) Option {
	return Option{
		apply: func(m *MockBuilder) error {
			m.cfg.mutex.Lock()
			defer m.cfg.mutex.Unlock()
			m.cfg.errorOnHeaderRequest = func(s beacon.Slot) error {
				if s >= slot {
					return fmt.Errorf("error generator")
				}
				return nil
			}
			return nil
		},
		description: fmt.Sprintf("WithErrorOnHeaderRequestAtSlot(%d)", slot),
	}
}

func WithErrorOnPayloadReveal(e ErrorProducer) Option {
	return Option{
		apply: func(m *MockBuilder) error {
			m.cfg.mutex.Lock()
			defer m.cfg.mutex.Unlock()
			m.cfg.errorOnPayloadReveal = e
			return nil
		},
		description: "WithErrorOnPayloadReveal",
	}
}

func WithErrorOnPayloadRevealAtEpoch(epoch beacon.Epoch) Option {
	return Option{
		apply: func(m *MockBuilder) error {
			m.cfg.mutex.Lock()
			defer m.cfg.mutex.Unlock()

			var spec = m.cfg.spec
			if spec == nil {
				return fmt.Errorf("unknown spec")
			}
			startSlot, err := spec.EpochStartSlot(epoch)
			if err != nil {
				return err
			}

			m.cfg.errorOnPayloadReveal = func(s beacon.Slot) error {
				if s >= startSlot {
					return fmt.Errorf("error generator")
				}
				return nil
			}
			return nil
		},
		description: fmt.Sprintf("WithErrorOnPayloadRevealAtEpoch(%d)", epoch),
	}
}

func WithErrorOnPayloadRevealAtSlot(slot beacon.Slot) Option {
	return Option{
		apply: func(m *MockBuilder) error {
			m.cfg.mutex.Lock()
			defer m.cfg.mutex.Unlock()

			m.cfg.errorOnPayloadReveal = func(s beacon.Slot) error {
				if s >= slot {
					return fmt.Errorf("error generator")
				}
				return nil
			}
			return nil
		},
		description: fmt.Sprintf("WithErrorOnPayloadRevealAtSlot(%d)", slot),
	}
}

// Specific function modifiers

type PayloadInvalidation string

const (
	INVALIDATE_PAYLOAD_STATE_ROOT   = "state_root"
	INVALIDATE_PAYLOAD_PARENT_HASH  = "parent_hash"
	INVALIDATE_PAYLOAD_COINBASE     = "coinbase"
	INVALIDATE_PAYLOAD_BASE_FEE     = "base_fee"
	INVALIDATE_PAYLOAD_UNCLE_HASH   = "uncle_hash"
	INVALIDATE_PAYLOAD_RECEIPT_HASH = "receipt_hash"
)

var PayloadInvalidationTypes = map[string]PayloadInvalidation{
	INVALIDATE_PAYLOAD_STATE_ROOT:   INVALIDATE_PAYLOAD_STATE_ROOT,
	INVALIDATE_PAYLOAD_PARENT_HASH:  INVALIDATE_PAYLOAD_PARENT_HASH,
	INVALIDATE_PAYLOAD_COINBASE:     INVALIDATE_PAYLOAD_COINBASE,
	INVALIDATE_PAYLOAD_BASE_FEE:     INVALIDATE_PAYLOAD_BASE_FEE,
	INVALIDATE_PAYLOAD_UNCLE_HASH:   INVALIDATE_PAYLOAD_UNCLE_HASH,
	INVALIDATE_PAYLOAD_RECEIPT_HASH: INVALIDATE_PAYLOAD_RECEIPT_HASH,
}

func PayloadInvalidationTypeNames() []string {
	res := make([]string, len(PayloadInvalidationTypes))
	i := 0
	for k := range PayloadInvalidationTypes {
		res[i] = k
		i += 1
	}
	return res
}

func genPayloadInvalidator(
	slot beacon.Slot,
	invType PayloadInvalidation,
) func(*api.ExecutableData, beacon.Slot) (bool, error) {
	return func(ed *api.ExecutableData, s beacon.Slot) (bool, error) {
		if s >= slot {
			if b, err := api.ExecutableDataToBlock(*ed); err != nil {
				return false, err
			} else {
				header := b.Header()

				switch invType {
				case INVALIDATE_PAYLOAD_STATE_ROOT:
					_, err = rand.Read(header.Root[:])
					copy(ed.StateRoot[:], header.Root[:])
				case INVALIDATE_PAYLOAD_PARENT_HASH:
					_, err = rand.Read(header.ParentHash[:])
					copy(ed.ParentHash[:], header.ParentHash[:])
				case INVALIDATE_PAYLOAD_COINBASE:
					_, err = rand.Read(header.Coinbase[:])
					copy(ed.FeeRecipient[:], header.Coinbase[:])
				case INVALIDATE_PAYLOAD_BASE_FEE:
					header.BaseFee.Add(header.BaseFee, big.NewInt(1))
					ed.BaseFeePerGas = header.BaseFee
				case INVALIDATE_PAYLOAD_UNCLE_HASH:
					_, err = rand.Read(header.UncleHash[:])
				case INVALIDATE_PAYLOAD_RECEIPT_HASH:
					_, err = rand.Read(header.ReceiptHash[:])
					copy(ed.ReceiptsRoot[:], header.ReceiptHash[:])
				default:
					panic(fmt.Errorf(
						"unknown invalidation type: %s",
						invType,
					))
				}
				if err != nil {
					panic(err)
				}
				modifiedHash := header.Hash()
				copy(ed.BlockHash[:], modifiedHash[:])
				return true, nil
			}
		}
		return false, nil
	}
}

func WithPayloadInvalidatorAtEpoch(
	epoch beacon.Epoch,
	invType PayloadInvalidation,
) Option {
	return Option{
		apply: func(m *MockBuilder) error {
			m.cfg.mutex.Lock()
			defer m.cfg.mutex.Unlock()

			if m.cfg.spec == nil {
				return fmt.Errorf("unknown spec")
			}
			startSlot, err := m.cfg.spec.EpochStartSlot(epoch)
			if err != nil {
				return err
			}

			pm := genPayloadInvalidator(startSlot, invType)
			m.cfg.payloadModifier = pm
			return nil
		},
		description: fmt.Sprintf("WithPayloadInvalidatorAtEpoch(%d)", epoch),
	}
}

func WithPayloadInvalidatorAtSlot(
	slot beacon.Slot,
	invType PayloadInvalidation,
) Option {
	return Option{
		apply: func(m *MockBuilder) error {
			m.cfg.mutex.Lock()
			defer m.cfg.mutex.Unlock()

			pm := genPayloadInvalidator(slot, invType)
			m.cfg.payloadModifier = pm
			return nil
		},
		description: fmt.Sprintf("WithPayloadInvalidatorAtSlot(%d)", slot),
	}
}

type PayloadAttributesInvalidation string

const (
	INVALIDATE_ATTR_REMOVE_WITHDRAWAL          = "remove_withdrawal"
	INVALIDATE_ATTR_EXTRA_WITHDRAWAL           = "extra_withdrawal"
	INVALIDATE_ATTR_WITHDRAWAL_ADDRESS         = "withdrawal_address"
	INVALIDATE_ATTR_WITHDRAWAL_AMOUNT          = "withdrawal_amount"
	INVALIDATE_ATTR_WITHDRAWAL_VALIDATOR_INDEX = "withdrawal_validator_index"
	INVALIDATE_ATTR_WITHDRAWAL_INDEX           = "withdrawal_index"
	INVALIDATE_ATTR_TIMESTAMP                  = "timestamp"
	INVALIDATE_ATTR_PREV_RANDAO                = "prevrandao"
	INVALIDATE_ATTR_RANDOM                     = "random"
)

var PayloadAttrInvalidationTypes = map[string]PayloadAttributesInvalidation{
	INVALIDATE_ATTR_REMOVE_WITHDRAWAL:          INVALIDATE_ATTR_REMOVE_WITHDRAWAL,
	INVALIDATE_ATTR_EXTRA_WITHDRAWAL:           INVALIDATE_ATTR_EXTRA_WITHDRAWAL,
	INVALIDATE_ATTR_WITHDRAWAL_ADDRESS:         INVALIDATE_ATTR_WITHDRAWAL_ADDRESS,
	INVALIDATE_ATTR_WITHDRAWAL_AMOUNT:          INVALIDATE_ATTR_WITHDRAWAL_AMOUNT,
	INVALIDATE_ATTR_WITHDRAWAL_VALIDATOR_INDEX: INVALIDATE_ATTR_WITHDRAWAL_VALIDATOR_INDEX,
	INVALIDATE_ATTR_WITHDRAWAL_INDEX:           INVALIDATE_ATTR_WITHDRAWAL_INDEX,
	INVALIDATE_ATTR_TIMESTAMP:                  INVALIDATE_ATTR_TIMESTAMP,
	INVALIDATE_ATTR_PREV_RANDAO:                INVALIDATE_ATTR_PREV_RANDAO,
	INVALIDATE_ATTR_RANDOM:                     INVALIDATE_ATTR_RANDOM,
}

func PayloadAttrInvalidationTypeNames() []string {
	res := make([]string, len(PayloadAttrInvalidationTypes))
	i := 0
	for k := range PayloadAttrInvalidationTypes {
		res[i] = k
		i += 1
	}
	return res
}

func genPayloadAttributesInvalidator(
	slot beacon.Slot,
	invType PayloadAttributesInvalidation,
	spec *beacon.Spec,
) func(*api.PayloadAttributes, beacon.Slot) (bool, error) {
	return func(pa *api.PayloadAttributes, s beacon.Slot) (bool, error) {
		if s >= slot {
			switch invType {
			case INVALIDATE_ATTR_WITHDRAWAL_ADDRESS,
				INVALIDATE_ATTR_WITHDRAWAL_AMOUNT,
				INVALIDATE_ATTR_WITHDRAWAL_VALIDATOR_INDEX,
				INVALIDATE_ATTR_WITHDRAWAL_INDEX,
				INVALIDATE_ATTR_REMOVE_WITHDRAWAL:
				if len(pa.Withdrawals) > 0 {
					switch invType {
					case INVALIDATE_ATTR_WITHDRAWAL_ADDRESS:
						pa.Withdrawals[0].Address[0]++
					case INVALIDATE_ATTR_WITHDRAWAL_AMOUNT:
						pa.Withdrawals[0].Amount++
					case INVALIDATE_ATTR_WITHDRAWAL_VALIDATOR_INDEX:
						pa.Withdrawals[0].Validator++
					case INVALIDATE_ATTR_WITHDRAWAL_INDEX:
						pa.Withdrawals[0].Index++
					case INVALIDATE_ATTR_REMOVE_WITHDRAWAL:
						pa.Withdrawals = pa.Withdrawals[1:]
					}
					return true, nil
				} else {
					return false, fmt.Errorf("unable to invalidate: no withdrawals")
				}
			case INVALIDATE_ATTR_EXTRA_WITHDRAWAL:
				if pa.Withdrawals == nil {
					pa.Withdrawals = make([]*types.Withdrawal, 0)
				}
				pa.Withdrawals = append(pa.Withdrawals, &types.Withdrawal{})
				return true, nil
			case INVALIDATE_ATTR_TIMESTAMP:
				pa.Timestamp = pa.Timestamp - uint64(
					spec.SECONDS_PER_SLOT*2,
				)
				return true, nil
			case INVALIDATE_ATTR_PREV_RANDAO, INVALIDATE_ATTR_RANDOM:
				_, err := rand.Read(pa.Random[:])
				if err != nil {
					panic(err)
				}
				return true, nil
			}
			panic(fmt.Errorf(
				"unknown invalidation type: %s",
				invType,
			))
		}
		return false, nil
	}
}

func WithPayloadAttributesInvalidatorAtEpoch(
	epoch beacon.Epoch,
	invType PayloadAttributesInvalidation,
) Option {
	return Option{
		apply: func(m *MockBuilder) error {
			m.cfg.mutex.Lock()
			defer m.cfg.mutex.Unlock()
			var spec = m.cfg.spec
			if spec == nil {
				return fmt.Errorf("unknown spec")
			}
			startSlot, err := spec.EpochStartSlot(epoch)
			if err != nil {
				return err
			}

			pm := genPayloadAttributesInvalidator(startSlot, invType, spec)
			m.cfg.payloadAttrModifier = pm
			return nil
		},
		description: fmt.Sprintf("WithPayloadInvalidatorAtEpoch(%d, %s)", epoch, invType),
	}
}

func WithPayloadAttributesInvalidatorAtSlot(
	slot beacon.Slot,
	invType PayloadAttributesInvalidation,
) Option {
	return Option{
		apply: func(m *MockBuilder) error {
			m.cfg.mutex.Lock()
			defer m.cfg.mutex.Unlock()
			if m.cfg.spec == nil {
				return fmt.Errorf("unknown spec")
			}

			pm := genPayloadAttributesInvalidator(slot, invType, m.cfg.spec)
			m.cfg.payloadAttrModifier = pm
			return nil
		},
		description: fmt.Sprintf("WithPayloadInvalidatorAtSlot(%d, %s)", slot, invType),
	}
}

func WithInvalidBuilderBidVersionAtSlot(
	activationSlot beacon.Slot,
) Option {
	return Option{
		apply: func(m *MockBuilder) error {
			m.cfg.mutex.Lock()
			defer m.cfg.mutex.Unlock()
			m.cfg.builderBidVersionResolver = func(slot beacon.Slot) (common.BuilderBid, string, error) {
				if slot >= activationSlot {
					// Always return Bellatrix, until theres a new fork that can override capella
					return &bellatrix.BuilderBid{}, "bellatrix", nil
				}
				return m.DefaultBuilderBidVersionResolver(slot)
			}

			return nil
		},
		description: fmt.Sprintf("WithInvalidBuilderBidVersionAtSlot(%d)", activationSlot),
	}
}

func WithInvalidBuilderBidVersionAtEpoch(
	activationEpoch beacon.Epoch,
) Option {
	return Option{
		apply: func(m *MockBuilder) error {
			m.cfg.mutex.Lock()
			defer m.cfg.mutex.Unlock()

			var spec = m.cfg.spec
			if spec == nil {
				return fmt.Errorf("unknown spec")
			}
			activationSlot, err := spec.EpochStartSlot(activationEpoch)
			if err != nil {
				return err
			}

			m.cfg.builderBidVersionResolver = func(slot beacon.Slot) (common.BuilderBid, string, error) {
				if slot >= activationSlot {
					// Always return Bellatrix, until theres a new fork that can override capella
					return &bellatrix.BuilderBid{}, "bellatrix", nil
				}
				return m.DefaultBuilderBidVersionResolver(slot)
			}

			return nil
		},
		description: fmt.Sprintf("WithInvalidBuilderBidVersionAtEpoch(%d)", activationEpoch),
	}
}

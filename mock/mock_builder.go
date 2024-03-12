package mock_builder

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"

	api "github.com/ethereum/go-ethereum/beacon/engine"
	el_common "github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/gorilla/mux"
	beacon_client "github.com/marioevz/eth-clients/clients/beacon"
	exec_client "github.com/marioevz/eth-clients/clients/execution"
	builder_types "github.com/marioevz/mock-builder/types"
	"github.com/marioevz/mock-builder/types/bellatrix"
	"github.com/marioevz/mock-builder/types/capella"
	"github.com/marioevz/mock-builder/types/common"
	"github.com/marioevz/mock-builder/types/deneb"
	blsu "github.com/protolambda/bls12-381-util"
	"github.com/protolambda/eth2api"
	beacon "github.com/protolambda/zrnt/eth2/beacon/common"
	"github.com/protolambda/ztyp/tree"
	"github.com/sirupsen/logrus"
)

var (
	DOMAIN_APPLICATION_BUILDER = beacon.BLSDomainType{0x00, 0x00, 0x00, 0x01}
	EMPTY_HASH                 = el_common.Hash{}
)

type MockBuilder struct {
	// Execution and consensus clients
	el *exec_client.ExecutionClient
	cl *beacon_client.BeaconClient

	// General properties
	srv              *http.Server
	sk               *blsu.SecretKey
	pk               *blsu.Pubkey
	pkBeacon         beacon.BLSPubkey
	builderApiDomain beacon.BLSDomain

	address string
	cancel  context.CancelFunc

	// Payload/Blocks history maps
	suggestedFeeRecipients          map[beacon.BLSPubkey]el_common.Address
	suggestedFeeRecipientsMutex     sync.Mutex
	requestedHeaders                map[beacon.Slot]GetHeaderRequestInfo
	requestedHeadersMutex           sync.Mutex
	builtPayloads                   map[beacon.Slot]common.BuilderBid
	builtPayloadsMutex              sync.Mutex
	modifiedPayloads                map[beacon.Slot]common.ExecutionPayload
	modifiedPayloadsMutex           sync.Mutex
	validatorPublicKeys             map[beacon.Slot]*beacon.BLSPubkey
	validatorPublicKeysMutex        sync.Mutex
	receivedSignedBeaconBlocks      map[beacon.Slot]common.SignedBeaconResponse
	receivedSignedBeaconBlocksMutex sync.Mutex
	signedBeaconBlock               map[tree.Root]bool
	signedBeaconBlockMutex          sync.Mutex
	validationErrors                map[beacon.Slot]error
	validationErrorsMutex           sync.Mutex

	// Configuration object
	cfg *config
}

type GetHeaderRequestInfo struct {
	Slot   beacon.Slot
	Parent el_common.Hash
	Pubkey beacon.BLSPubkey
}

var _ builder_types.Builder = (*MockBuilder)(nil)

const (
	DEFAULT_BUILDER_HOST = "0.0.0.0"
	DEFAULT_BUILDER_PORT = 18550
)

func NewMockBuilder(
	ctx context.Context,
	el *exec_client.ExecutionClient,
	cl *beacon_client.BeaconClient,
	opts ...Option,
) (*MockBuilder, error) {
	if el == nil {
		panic(fmt.Errorf("invalid EL provided: nil"))
	}
	var (
		err error
	)

	m := &MockBuilder{
		el: el,
		cl: cl,

		suggestedFeeRecipients: make(
			map[beacon.BLSPubkey]el_common.Address,
		),
		requestedHeaders:    make(map[beacon.Slot]GetHeaderRequestInfo),
		builtPayloads:       make(map[beacon.Slot]common.BuilderBid),
		modifiedPayloads:    make(map[beacon.Slot]common.ExecutionPayload),
		validatorPublicKeys: make(map[beacon.Slot]*beacon.BLSPubkey),
		receivedSignedBeaconBlocks: make(
			map[beacon.Slot]common.SignedBeaconResponse,
		),
		signedBeaconBlock: make(map[tree.Root]bool),
		validationErrors:  make(map[beacon.Slot]error),

		cfg: &config{
			host:              DEFAULT_BUILDER_HOST,
			port:              DEFAULT_BUILDER_PORT,
			getPayloadDelayMs: 200,
			minimumValue:      big.NewInt(1),
		},
	}

	for _, o := range opts {
		if err = o.apply(m); err != nil {
			return nil, err
		}
	}

	if m.cfg.spec == nil {
		return nil, fmt.Errorf("no spec configured")
	}
	m.builderApiDomain = beacon.ComputeDomain(
		DOMAIN_APPLICATION_BUILDER,
		m.cfg.spec.GENESIS_FORK_VERSION,
		tree.Root{},
	)

	// static builder key
	skByte := [32]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f}
	sk := blsu.SecretKey{}
	err = (&sk).Deserialize(&skByte)
	if err != nil {
		panic(fmt.Errorf("unable to deserialize %v", err))
	}
	m.sk = &sk
	if m.pk, err = blsu.SkToPk(m.sk); err != nil {
		panic(err)
	}
	pkBytes := m.pk.Serialize()
	copy(m.pkBeacon[:], pkBytes[:])

	router := mux.NewRouter()

	// Builder API
	router.HandleFunc("/eth/v1/builder/validators", m.HandleValidators).
		Methods("POST")
	router.HandleFunc("/eth/v1/builder/header/{slot:[0-9]+}/{parenthash}/{pubkey}", m.HandleGetExecutionPayloadHeader).
		Methods("GET")
	router.HandleFunc("/eth/v1/builder/blinded_blocks", m.HandleSubmitBlindedBlock).
		Methods("POST")
	router.HandleFunc("/eth/v1/builder/status", m.HandleStatus).Methods("GET")

	// Mock customization
	// Error on payload request
	router.HandleFunc("/mock/errors/payload_request", m.HandleMockDisableErrorOnHeaderRequest).
		Methods("DELETE")
	router.HandleFunc("/mock/errors/payload_request", m.HandleMockEnableErrorOnHeaderRequest).
		Methods("POST")
	router.HandleFunc(
		"/mock/errors/payload_request/slot/{slot:[0-9]+}",
		m.HandleMockEnableErrorOnHeaderRequest,
	).Methods("POST")
	router.HandleFunc(
		"/mock/errors/payload_request/epoch/{epoch:[0-9]+}",
		m.HandleMockEnableErrorOnHeaderRequest,
	).Methods("POST")

	// Error on block submission
	router.HandleFunc("/mock/errors/payload_reveal", m.HandleMockDisableErrorOnPayloadReveal).
		Methods("DELETE")
	router.HandleFunc("/mock/errors/payload_reveal", m.HandleMockEnableErrorOnPayloadReveal).
		Methods("POST")
	router.HandleFunc(
		"/mock/errors/payload_reveal/slot/{slot:[0-9]+}",
		m.HandleMockEnableErrorOnPayloadReveal,
	).Methods("POST")
	router.HandleFunc(
		"/mock/errors/payload_reveal/epoch/{epoch:[0-9]+}",
		m.HandleMockEnableErrorOnPayloadReveal,
	).Methods("POST")

	// Invalidate payload attributes
	router.HandleFunc("/mock/invalid/payload_attributes", m.HandleMockDisableInvalidatePayloadAttributes).
		Methods("DELETE")
	router.HandleFunc(
		"/mock/invalid/payload_attributes/{type}",
		m.HandleMockEnableInvalidatePayloadAttributes,
	).Methods("POST")
	router.HandleFunc(
		"/mock/invalid/payload_attributes/{type}/slot/{slot:[0-9]+}",
		m.HandleMockEnableInvalidatePayloadAttributes,
	).Methods("POST")
	router.HandleFunc(
		"/mock/invalid/payload_attributes/{type}/epoch/{epoch:[0-9]+}",
		m.HandleMockEnableInvalidatePayloadAttributes,
	).Methods("POST")

	// Invalidate payload
	router.HandleFunc("/mock/invalid/payload", m.HandleMockDisableInvalidatePayload).
		Methods("DELETE")
	router.HandleFunc(
		"/mock/invalid/payload/{type}",
		m.HandleMockEnableInvalidatePayload,
	).Methods("POST")
	router.HandleFunc(
		"/mock/invalid/payload/{type}/slot/{slot:[0-9]+}",
		m.HandleMockEnableInvalidatePayload,
	).Methods("POST")
	router.HandleFunc(
		"/mock/invalid/payload/{type}/epoch/{epoch:[0-9]+}",
		m.HandleMockEnableInvalidatePayload,
	).Methods("POST")

	// Statistics Handlers
	router.HandleFunc("/mock/stats/validation_errors", m.HandleValidationErrors).Methods("GET")

	m.srv = &http.Server{
		Handler: router,
		Addr:    fmt.Sprintf("%s:%d", m.cfg.host, m.cfg.port),
	}

	ctx, cancel := context.WithCancel(ctx)
	go func() {
		if err := m.Start(ctx); err != nil && err != context.Canceled {
			panic(err)
		}
	}()
	m.cancel = cancel

	return m, nil
}

func (m *MockBuilder) Cancel() error {
	if m.cancel != nil {
		m.cancel()
	}
	return nil
}

func (m *MockBuilder) DefaultBuilderBidVersionResolver(
	slot beacon.Slot,
) (builderBid common.BuilderBid, err error) {
	if m.cfg.spec.SlotToEpoch(slot) >= m.cfg.spec.DENEB_FORK_EPOCH {
		return &deneb.BuilderBid{}, nil
	} else if m.cfg.spec.SlotToEpoch(slot) >= m.cfg.spec.CAPELLA_FORK_EPOCH {
		return &capella.BuilderBid{}, nil
	} else if m.cfg.spec.SlotToEpoch(slot) >= m.cfg.spec.BELLATRIX_FORK_EPOCH {
		return &bellatrix.BuilderBid{}, nil
	}
	return nil, fmt.Errorf("payload requested from improper fork")
}

func KZGCommitmentsToVersionedHashes(version byte, kzgCommitments []hexutil.Bytes) []el_common.Hash {
	versionedHashes := make([]el_common.Hash, len(kzgCommitments))
	for i, kzgCommitment := range kzgCommitments {
		sha256Hash := sha256.Sum256(kzgCommitment[:])
		versionedHashes[i] = el_common.BytesToHash(append([]byte{version}, sha256Hash[1:]...))
	}
	return versionedHashes
}

// Start a proxy server.
func (m *MockBuilder) Start(ctx context.Context) error {
	m.srv.BaseContext = func(listener net.Listener) context.Context {
		return ctx
	}
	var (
		el_address = "unknown yet"
		cl_address = "unknown yet"
	)

	if addr, err := m.el.EngineRPCAddress(); err == nil {
		el_address = addr
	} else {
		logrus.Error(err)
	}
	if addr, err := m.cl.BeaconAPIURL(); err == nil {
		cl_address = addr
	} else {
		logrus.Error(err)
	}
	fields := logrus.Fields{
		"builder_id":           m.cfg.id,
		"address":              m.address,
		"port":                 m.cfg.port,
		"pubkey":               m.pkBeacon.String(),
		"el_address":           el_address,
		"cl_address":           cl_address,
		"get-payload-delay-ms": m.cfg.getPayloadDelayMs,
	}
	if m.cfg.extraDataWatermark != "" {
		fields["extra-data"] = m.cfg.extraDataWatermark
	}
	logrus.WithFields(fields).Info("Builder now listening")
	go func() {
		if err := m.srv.ListenAndServe(); err != nil {
			logrus.WithFields(logrus.Fields{
				"builder_id": m.cfg.id,
			}).Error(err)
		}
	}()
	for {
		<-ctx.Done()
		return m.srv.Shutdown(ctx)
	}
}

func (m *MockBuilder) Address() string {
	return fmt.Sprintf(
		"http://%s@%v:%d",
		m.pkBeacon.String(),
		m.cfg.externalIP,
		m.cfg.port,
	)
}

func (m *MockBuilder) GetBuiltPayloadsCount() int {
	return len(m.builtPayloads)
}

func (m *MockBuilder) GetSignedBeaconBlockCount() int {
	return len(m.signedBeaconBlock)
}

func (m *MockBuilder) GetBuiltPayloads() map[beacon.Slot]common.BuilderBid {
	mapCopy := make(map[beacon.Slot]common.BuilderBid)
	for k, v := range m.builtPayloads {
		mapCopy[k] = v
	}
	return mapCopy
}

func (m *MockBuilder) GetModifiedPayloads() map[beacon.Slot]common.ExecutionPayload {
	mapCopy := make(map[beacon.Slot]common.ExecutionPayload)
	for k, v := range m.modifiedPayloads {
		mapCopy[k] = v
	}
	return mapCopy
}

func (m *MockBuilder) GetSignedBeaconBlock(slot beacon.Slot) (common.SignedBeaconResponse, bool) {
	m.receivedSignedBeaconBlocksMutex.Lock()
	defer m.receivedSignedBeaconBlocksMutex.Unlock()
	signedBeaconResponse, ok := m.receivedSignedBeaconBlocks[slot]
	return signedBeaconResponse, ok
}

func (m *MockBuilder) GetSignedBeaconBlocks() map[beacon.Slot]common.SignedBeaconResponse {
	m.receivedSignedBeaconBlocksMutex.Lock()
	defer m.receivedSignedBeaconBlocksMutex.Unlock()
	mapCopy := make(map[beacon.Slot]common.SignedBeaconResponse)
	for k, v := range m.receivedSignedBeaconBlocks {
		mapCopy[k] = v
	}
	return mapCopy
}

func (m *MockBuilder) GetValidationErrors() map[beacon.Slot]error {
	m.validationErrorsMutex.Lock()
	defer m.validationErrorsMutex.Unlock()
	mapCopy := make(map[beacon.Slot]error)
	for k, v := range m.validationErrors {
		mapCopy[k] = v
	}
	return mapCopy
}

func (m *MockBuilder) GetValidationErrorsCount() int {
	return len(m.validationErrors)
}

func (m *MockBuilder) GetHeaderRequests() map[beacon.Slot]GetHeaderRequestInfo {
	m.requestedHeadersMutex.Lock()
	defer m.requestedHeadersMutex.Unlock()
	mapCopy := make(map[beacon.Slot]GetHeaderRequestInfo)
	for k, v := range m.requestedHeaders {
		mapCopy[k] = v
	}
	return mapCopy
}

func (m *MockBuilder) HandleValidators(
	w http.ResponseWriter,
	req *http.Request,
) {
	requestBytes, err := io.ReadAll(req.Body)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"builder_id": m.cfg.id,
			"err":        err,
		}).Error("Unable to read request body")
		http.Error(w, "Unable to read request body", http.StatusBadRequest)
		return
	}
	var signedValidatorRegistrations []common.SignedValidatorRegistrationV1
	if err := json.Unmarshal(requestBytes, &signedValidatorRegistrations); err != nil {
		logrus.WithFields(logrus.Fields{
			"builder_id": m.cfg.id,
			"err":        err,
		}).Error("Unable to parse request body")
		http.Error(w, "Unable to parse request body", http.StatusBadRequest)
		return
	}

	for _, vr := range signedValidatorRegistrations {
		// Verify signature
		signingRoot := beacon.ComputeSigningRoot(
			vr.Message.HashTreeRoot(tree.GetHashFn()),
			m.builderApiDomain,
		)

		pk, err := vr.Message.PubKey.Pubkey()
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"builder_id": m.cfg.id,
				"err":        err,
			}).Error("Unable to deserialize pubkey")
			http.Error(
				w,
				"Unable to deserialize pubkey",
				http.StatusBadRequest,
			)
			return
		}

		sig, err := vr.Signature.Signature()
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"builder_id": m.cfg.id,
				"err":        err,
			}).Error("Unable to deserialize signature")
			http.Error(
				w,
				"Unable to deserialize signature",
				http.StatusBadRequest,
			)
			return
		}

		if !blsu.Verify(pk, signingRoot[:], sig) {
			logrus.WithFields(logrus.Fields{
				"builder_id":    m.cfg.id,
				"pubkey":        vr.Message.PubKey,
				"fee_recipient": vr.Message.FeeRecipient,
				"timestamp":     vr.Message.Timestamp,
				"gas_limit":     vr.Message.GasLimit,
				"signature":     vr.Signature,
			}).Error("Unable to verify signature")
			http.Error(
				w,
				"Unable to verify signature",
				http.StatusBadRequest,
			)
			return
		}
		var addr el_common.Address
		copy(addr[:], vr.Message.FeeRecipient[:])
		m.suggestedFeeRecipientsMutex.Lock()
		m.suggestedFeeRecipients[vr.Message.PubKey] = addr
		m.suggestedFeeRecipientsMutex.Unlock()
	}
	logrus.WithFields(logrus.Fields{
		"builder_id":      m.cfg.id,
		"validator_count": len(signedValidatorRegistrations),
	}).Info(
		"Received validator registrations",
	)
	w.WriteHeader(http.StatusOK)

}

func (m *MockBuilder) SlotToTimestamp(slot beacon.Slot) uint64 {
	return uint64(
		m.cfg.beaconGenesisTime + beacon.Timestamp(
			slot,
		)*beacon.Timestamp(
			m.cfg.spec.SECONDS_PER_SLOT,
		),
	)
}

type PayloadHeaderRequestVarsParser map[string]string

func (vars PayloadHeaderRequestVarsParser) Slot() (slot beacon.Slot, err error) {
	if slotStr, ok := vars["slot"]; ok {
		err = (&slot).UnmarshalJSON([]byte(slotStr))
	} else {
		err = fmt.Errorf("no slot")
	}
	return slot, err
}

func (vars PayloadHeaderRequestVarsParser) PubKey() (pubkey beacon.BLSPubkey, err error) {
	if pubkeyStr, ok := vars["pubkey"]; ok {
		err = (&pubkey).UnmarshalText([]byte(pubkeyStr))
	} else {
		err = fmt.Errorf("no pubkey")
	}
	return pubkey, err
}

func (vars PayloadHeaderRequestVarsParser) ParentHash() (el_common.Hash, error) {
	if parentHashStr, ok := vars["parenthash"]; ok {
		return el_common.HexToHash(parentHashStr), nil
	}
	return el_common.Hash{}, fmt.Errorf("no parent_hash")
}

func (m *MockBuilder) HandleGetExecutionPayloadHeader(
	w http.ResponseWriter, req *http.Request,
) {
	var (
		payloadModified = false
		vars            = PayloadHeaderRequestVarsParser(mux.Vars(req))

		// Context related vars
		ctx    context.Context
		cancel context.CancelFunc
	)

	slot, err := vars.Slot()
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"builder_id": m.cfg.id,
			"err":        err,
		}).Error("Unable to parse request url")
		http.Error(
			w,
			"Unable to parse request url",
			http.StatusBadRequest,
		)
		return
	}

	parentHash, err := vars.ParentHash()
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"builder_id": m.cfg.id,
			"err":        err,
		}).Error("Unable to parse request url")
		http.Error(
			w,
			"Unable to parse request url",
			http.StatusBadRequest,
		)
		return
	}

	pubkey, err := vars.PubKey()
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"builder_id": m.cfg.id,
			"err":        err,
		}).Error("Unable to parse request url")
		http.Error(
			w,
			"Unable to parse request url",
			http.StatusBadRequest,
		)
		return
	}

	logrus.WithFields(logrus.Fields{
		"builder_id":  m.cfg.id,
		"slot":        slot,
		"parent_hash": parentHash,
		"pubkey":      pubkey,
	}).Info(
		"Received request for header",
	)
	// Save the validator public key
	m.validatorPublicKeysMutex.Lock()
	m.validatorPublicKeys[slot] = &pubkey
	m.validatorPublicKeysMutex.Unlock()

	// Add the request to the history
	m.requestedHeadersMutex.Lock()
	m.requestedHeaders[slot] = GetHeaderRequestInfo{
		Slot:   slot,
		Parent: parentHash,
		Pubkey: pubkey,
	}
	m.requestedHeadersMutex.Unlock()

	// Engine API Directive Versions and information required to build the payload
	var (
		getPayloadVersion        int    = 1
		forkchoiceUpdatedVersion int    = 1
		blobCommitmentVersion    byte   = 1
		fork                     string = "bellatrix"

		// Payload building requirements
		withdrawalsRequired = false
		beaconRootRequired  = false
	)

	// Determine Engine API Versions
	if m.cfg.spec.SlotToEpoch(slot) >= m.cfg.spec.DENEB_FORK_EPOCH {
		getPayloadVersion = 3
		forkchoiceUpdatedVersion = 3
		fork = "deneb"
	} else if m.cfg.spec.SlotToEpoch(slot) >= m.cfg.spec.CAPELLA_FORK_EPOCH {
		getPayloadVersion = 2
		forkchoiceUpdatedVersion = 2
		fork = "capella"
	}

	// Set requirements
	if m.cfg.spec.SlotToEpoch(slot) >= m.cfg.spec.DENEB_FORK_EPOCH {
		beaconRootRequired = true
	}
	if m.cfg.spec.SlotToEpoch(slot) >= m.cfg.spec.CAPELLA_FORK_EPOCH {
		withdrawalsRequired = true
	}

	// Gather all required information from the CL
	var (
		stateId     = eth2api.StateHead
		blockId     = eth2api.BlockHead
		randaoMix   *tree.Root
		withdrawals beacon.Withdrawals
		blockHead   *beacon_client.VersionedSignedBeaconBlock
	)

	randaoMix, err = m.cl.StateRandaoMix(context.Background(), stateId)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"builder_id": m.cfg.id,
			"slot":       slot,
			"err":        err,
		}).Info("Error getting randao mix from CL, will fallback to try to get the full state")
	}

	if withdrawalsRequired {
		withdrawals, err = m.cl.ExpectedWithdrawals(context.Background(), stateId)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"builder_id": m.cfg.id,
				"slot":       slot,
				"err":        err,
			}).Info("Error getting expected withdrawals from CL, will fallback to try to get the full state")
		}
	}

	blockHead, err = m.cl.BlockV2(context.Background(), blockId)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"builder_id": m.cfg.id,
			"slot":       slot,
			"err":        err,
		}).Error("Error getting block from CL")
		http.Error(
			w,
			"Unable to respond to header request",
			http.StatusInternalServerError,
		)
		return
	}

	if randaoMix == nil || (withdrawalsRequired && withdrawals == nil) {
		// We are missing information from the CL, request the full state to reproduce
		// it from there
		ctx, cancel = context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		state, err := m.cl.BeaconStateV2(ctx, stateId)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"builder_id": m.cfg.id,
				"slot":       slot,
				"err":        err,
			}).Error("Error getting beacon state from CL")
			http.Error(
				w,
				"Unable to respond to header request",
				http.StatusInternalServerError,
			)
			return
		}

		// PrevRandao
		if randaoMix == nil {
			prevRandaoMixes := state.RandaoMixes()
			randaoMix = &prevRandaoMixes[m.cfg.spec.SlotToEpoch(slot-1)]
		}

		// Withdrawals
		if withdrawalsRequired && withdrawals == nil {
			withdrawals, err = state.NextWithdrawals(slot)
			if err != nil {
				logrus.WithFields(logrus.Fields{
					"builder_id": m.cfg.id,
					"slot":       slot,
					"err":        err,
				}).Error("Error getting next withdrawals from state")
				http.Error(
					w,
					"Unable to respond to header request",
					http.StatusInternalServerError,
				)
				return
			}
		}
	}

	var forkchoiceState *api.ForkchoiceStateV1
	if bytes.Equal(parentHash[:], EMPTY_HASH[:]) {
		// Edge case where the CL is requesting us to build the very first block
		ctx, cancel = context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		genesis, err := m.el.BlockByNumber(ctx, nil)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"builder_id": m.cfg.id,
				"err":        err,
			}).Error("Error getting latest block from the EL")
			http.Error(
				w,
				"Unable to respond to header request",
				http.StatusInternalServerError,
			)
			return
		}
		forkchoiceState = &api.ForkchoiceStateV1{
			HeadBlockHash: genesis.Hash(),
		}
	} else {
		// Check if we have the correct beacon state
		latestExecPayloadHeaderHash := blockHead.ExecutionPayloadBlockHash()
		if !bytes.Equal(latestExecPayloadHeaderHash[:], parentHash[:]) {
			logrus.WithFields(logrus.Fields{
				"builder_id":                  m.cfg.id,
				"latestExecPayloadHeaderHash": latestExecPayloadHeaderHash.String(),
				"parentHash":                  parentHash.String(),
				"err":                         "beacon state latest execution payload hash and parent hash requested don't match",
			}).Error("Unable to respond to header request")
			http.Error(
				w,
				"Unable to respond to header request",
				http.StatusInternalServerError,
			)
			return
		}

		// Check if we know the latest forkchoice updated
		forkchoiceState, err = m.el.GetLatestForkchoiceUpdated(context.Background())
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"builder_id": m.cfg.id,
				"err":        err,
			}).Error("error getting the latest forkchoiceUpdated")
			http.Error(
				w,
				"Unable to respond to header request",
				http.StatusInternalServerError,
			)
			return
		} else if forkchoiceState == nil {
			logrus.WithFields(logrus.Fields{
				"builder_id": m.cfg.id,
			}).Error("unable to get the latest forkchoiceUpdated")
			http.Error(
				w,
				"Unable to respond to header request",
				http.StatusInternalServerError,
			)
			return
		} else if bytes.Equal(forkchoiceState.HeadBlockHash[:], EMPTY_HASH[:]) {
			logrus.WithFields(logrus.Fields{
				"builder_id": m.cfg.id,
			}).Error("latest forkchoiceUpdated contains zero'd head")
			http.Error(
				w,
				"Unable to respond to header request",
				http.StatusInternalServerError,
			)
			return
		}

		// Check if the requested parent matches the last fcu
		if !bytes.Equal(forkchoiceState.HeadBlockHash[:], parentHash[:]) {
			logrus.WithFields(logrus.Fields{
				"builder_id": m.cfg.id,
				"err":        "last fcu head and requested parent don't match",
				"head":       forkchoiceState.HeadBlockHash.String(),
				"parent":     parentHash.String(),
			}).Error("Unable to respond to header request")
			http.Error(
				w,
				"Unable to respond to header request",
				http.StatusInternalServerError,
			)
			return
		}

	}

	// Build payload attributes
	pAttr := api.PayloadAttributes{
		Timestamp:             m.SlotToTimestamp(slot),
		SuggestedFeeRecipient: m.suggestedFeeRecipients[pubkey],
	}

	// Withdrawals
	if withdrawalsRequired {
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"builder_id": m.cfg.id,
				"err":        err,
			}).Error("Unable to obtain correct list of withdrawals")
			http.Error(
				w,
				"Unable to respond to header request",
				http.StatusInternalServerError,
			)
			return
		}
		pAttr.Withdrawals = make(types.Withdrawals, len(withdrawals))
		for i, w := range withdrawals {
			newWithdrawal := types.Withdrawal{}
			copy(newWithdrawal.Address[:], w.Address[:])
			newWithdrawal.Amount = uint64(w.Amount)
			newWithdrawal.Index = uint64(w.Index)
			newWithdrawal.Validator = uint64(w.ValidatorIndex)
			pAttr.Withdrawals[i] = &newWithdrawal
		}
	}
	// Beacon Root for Deneb
	if beaconRootRequired {
		h := blockHead.Root()
		pAttr.BeaconRoot = new(el_common.Hash)
		copy(pAttr.BeaconRoot[:], h[:])
	}

	// Copy randaoMix
	copy(pAttr.Random[:], randaoMix[:])

	m.cfg.mutex.Lock()
	payloadAttrModifier := m.cfg.payloadAttrModifier
	m.cfg.mutex.Unlock()
	if payloadAttrModifier != nil {
		if mod, err := payloadAttrModifier(&pAttr, slot); err != nil {
			logrus.WithFields(logrus.Fields{
				"builder_id": m.cfg.id,
				"err":        err,
			}).Error("Unable to modify payload attributes using modifier")
			http.Error(
				w,
				"Unable to respond to header request",
				http.StatusInternalServerError,
			)
			return
		} else if mod {
			logrus.WithFields(logrus.Fields{
				"builder_id": m.cfg.id,
				"slot":       slot,
			}).Info("Modified payload attributes")
			payloadModified = true
		}
	}

	logrus.WithFields(logrus.Fields{
		"builder_id":            m.cfg.id,
		"Timestamp":             pAttr.Timestamp,
		"PrevRandao":            pAttr.Random,
		"SuggestedFeeRecipient": pAttr.SuggestedFeeRecipient,
		"Withdrawals":           pAttr.Withdrawals,
		"BeaconRoot":            pAttr.BeaconRoot,
		"fork":                  fork,
	}).Info("Built payload attributes for header")

	// Request a payload from the execution client
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	r, err := m.el.EngineForkchoiceUpdated(
		ctx,
		forkchoiceState,
		&pAttr,
		forkchoiceUpdatedVersion,
	)
	if err != nil || r.PayloadID == nil {
		fcuJson, _ := json.MarshalIndent(forkchoiceState, "", " ")
		logrus.WithFields(logrus.Fields{
			"builder_id":      m.cfg.id,
			"err":             err,
			"forkchoiceState": string(fcuJson),
			"payloadID":       r.PayloadID,
		}).Error("Error on ForkchoiceUpdated to EL")
		http.Error(
			w,
			"Unable to respond to header request",
			http.StatusInternalServerError,
		)
		return
	}

	// Wait for EL to produce payload
	logrus.WithFields(logrus.Fields{
		"builder_id": m.cfg.id,
		"payloadID":  r.PayloadID.String(),
		"fork":       fork,
		"DelayMs":    m.cfg.getPayloadDelayMs,
	}).Info("Waiting for payload from EL")

	time.Sleep(time.Duration(m.cfg.getPayloadDelayMs) * time.Millisecond)

	// Request payload from the EL
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	p, bValue, apiBlobsBundle, _, err := m.el.EngineGetPayload(ctx, r.PayloadID, getPayloadVersion)
	if err != nil || p == nil {
		logrus.WithFields(logrus.Fields{
			"builder_id": m.cfg.id,
			"err":        err,
			"payload":    p,
		}).Error("Error on GetPayload to EL")
		http.Error(
			w,
			"Unable to respond to header request",
			http.StatusInternalServerError,
		)
		return
	}

	// Blob bundle and versioned hashes
	var versionedHashes []el_common.Hash
	if apiBlobsBundle != nil {
		versionedHashes = KZGCommitmentsToVersionedHashes(blobCommitmentVersion, apiBlobsBundle.Commitments)
	}

	// Watermark payload
	if m.cfg.extraDataWatermark != "" {
		if err := ModifyExtraData(p, versionedHashes, pAttr.BeaconRoot, []byte(m.cfg.extraDataWatermark)); err != nil {
			logrus.WithFields(logrus.Fields{
				"builder_id": m.cfg.id,
				"err":        err,
			}).Error("Error modifying payload")
			http.Error(
				w,
				"Unable to respond to header request",
				http.StatusInternalServerError,
			)
			return
		}
	}

	// Modify the payload if necessary
	m.cfg.mutex.Lock()
	payloadModifier := m.cfg.payloadModifier
	m.cfg.mutex.Unlock()
	if payloadModifier != nil {
		oldHash := p.BlockHash
		if mod, err := payloadModifier(p, versionedHashes, apiBlobsBundle, pAttr.BeaconRoot, slot); err != nil {
			logrus.WithFields(logrus.Fields{
				"builder_id": m.cfg.id,
				"err":        err,
			}).Error("Error modifying payload")
			http.Error(
				w,
				"Unable to respond to header request",
				http.StatusInternalServerError,
			)
			return
		} else if mod {
			logrus.WithFields(logrus.Fields{
				"builder_id":    m.cfg.id,
				"slot":          slot,
				"previous_hash": oldHash.String(),
				"new_hash":      p.BlockHash.String(),
			}).Info("Modified payload")
			payloadModified = true
		}
	}

	// We are ready to respond to the CL
	var builderBid common.BuilderBid

	m.cfg.mutex.Lock()
	builderBidVersionResolver := m.cfg.builderBidVersionResolver
	m.cfg.mutex.Unlock()
	if builderBidVersionResolver == nil {
		builderBidVersionResolver = m.DefaultBuilderBidVersionResolver
	}

	builderBid, err = builderBidVersionResolver(slot)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"builder_id": m.cfg.id,
			"err":        err,
		}).Error("Error getting builder bid version")
		http.Error(
			w,
			"Unable to respond to header request",
			http.StatusInternalServerError,
		)
		return
	}

	// Get proposer index to add it to the context
	proposerIndex, err := m.cl.ProposerIndex(ctx, slot)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"builder_id": m.cfg.id,
			"err":        err,
			"slot":       slot,
		}).Error("Error getting proposer index from CL")
		http.Error(
			w,
			"Unable to respond to header request",
			http.StatusInternalServerError,
		)
		return
	}

	if err = builderBid.Build(m.cfg.spec, p, apiBlobsBundle, blockHead.Root(), slot, proposerIndex); err != nil {
		logrus.WithFields(logrus.Fields{
			"builder_id": m.cfg.id,
			"err":        err,
		}).Error("Error building bid from execution data")
		http.Error(
			w,
			"Unable to respond to header request",
			http.StatusInternalServerError,
		)
		return
	}

	if m.cfg.payloadWeiValueModifier != nil {
		// If requested, fake a higher gwei so the CL always takes the bid
		bValue, err = m.cfg.payloadWeiValueModifier(bValue)
		if err != nil {
			logrus.WithFields(logrus.Fields{
				"builder_id": m.cfg.id,
				"err":        err,
			}).Error("Error modifiying bid")
			http.Error(
				w,
				"Unable to respond to header request",
				http.StatusInternalServerError,
			)
			return
		}
	}
	if bValue.Cmp(m.cfg.minimumValue) < 0 {
		// Always set at least the minimum value
		builderBid.SetValue(m.cfg.minimumValue)
	} else {
		builderBid.SetValue(bValue)
	}
	builderBid.SetPubKey(m.pkBeacon)

	payloadFields := logrus.Fields{
		"builder_id": m.cfg.id,
		"payload":    p.BlockHash.String(),
		"value":      bValue.String(),
		"fork":       fork,
	}
	if p.BlobGasUsed != nil {
		payloadFields["blob_gas_used"] = *p.BlobGasUsed
	}
	logrus.WithFields(payloadFields).Info("Built payload from EL")

	builtBidRoot := builderBid.HashTreeRoot(m.cfg.spec, tree.GetHashFn())
	bidJson, _ := json.Marshal(builderBid)
	logrus.WithFields(logrus.Fields{
		"builder_id": m.cfg.id,
		"bid_root":   builtBidRoot,
		"json":       string(bidJson),
	}).Debug("Built bid details")

	signedBid, err := builderBid.Sign(m.cfg.spec, m.builderApiDomain, m.sk, m.pk)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"builder_id": m.cfg.id,
			"err":        err,
		}).Error("Error signing bid from execution data")
		http.Error(
			w,
			"Unable to respond to header request",
			http.StatusInternalServerError,
		)
		return
	}

	// Check if we are supposed to simulate an error
	m.cfg.mutex.Lock()
	errOnHeadeReq := m.cfg.errorOnHeaderRequest
	m.cfg.mutex.Unlock()
	if errOnHeadeReq != nil {
		if err := errOnHeadeReq(slot); err != nil {
			logrus.WithFields(logrus.Fields{
				"builder_id": m.cfg.id,
				"slot":       slot,
				"err":        err,
			}).Error("Simulated error")
			http.Error(
				w,
				"Unable to respond to header request",
				http.StatusInternalServerError,
			)
			return
		}
	}

	versionedSignedBid := signedBid.Versioned()

	logrus.WithFields(logrus.Fields{
		"builder_id": m.cfg.id,
		"fork":       fork,
		"bid":        versionedSignedBid,
	}).Info("Built blinded bid to CL")

	if err = serveJSON(w, versionedSignedBid); err != nil {
		logrus.WithFields(logrus.Fields{
			"builder_id": m.cfg.id,
			"err":        err,
		}).Error("Error writing JSON response to CL")
		http.Error(
			w,
			"Unable to respond to header request",
			http.StatusInternalServerError,
		)
		return
	}

	// Finally add the execution payload to the cache
	m.builtPayloadsMutex.Lock()
	m.builtPayloads[slot] = builderBid
	m.builtPayloadsMutex.Unlock()
	if payloadModified {
		m.modifiedPayloadsMutex.Lock()
		m.modifiedPayloads[slot] = builderBid.FullPayload()
		m.modifiedPayloadsMutex.Unlock()
	}
	logrus.Debug("Finished serving header request")
}

type SlotEnvelope struct {
	Slot beacon.Slot `json:"slot" yaml:"slot"`
}

type MessageSlotEnvelope struct {
	SlotEnvelope SlotEnvelope `json:"message" yaml:"message"`
}

type DenebMessageSlotEnvelope struct {
	MessageSlotEnvelope MessageSlotEnvelope `json:"signed_blinded_block" yaml:"signed_blinded_block"`
}

func (m *MockBuilder) HandleSubmitBlindedBlock(
	w http.ResponseWriter, req *http.Request,
) {
	logrus.WithFields(logrus.Fields{
		"builder_id": m.cfg.id,
	}).Info(
		"Received submission for blinded blocks",
	)
	requestBytes, err := io.ReadAll(req.Body)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"builder_id": m.cfg.id,
			"err":        err,
		}).Error("Unable to read request body")
		http.Error(w, "Unable to read request body", http.StatusBadRequest)
		return
	}

	// First try to find out the slot to get the version of the block
	var slot beacon.Slot
	{
		var messageSlotEnvelope MessageSlotEnvelope
		if err := json.Unmarshal(requestBytes, &messageSlotEnvelope); err == nil {
			slot = messageSlotEnvelope.SlotEnvelope.Slot
		}

		if slot == 0 {
			// Try with deneb
			var denebMessageSlotEnvelope DenebMessageSlotEnvelope
			if err := json.Unmarshal(requestBytes, &denebMessageSlotEnvelope); err == nil {
				slot = denebMessageSlotEnvelope.MessageSlotEnvelope.SlotEnvelope.Slot
			}
		}
	}

	var (
		signedBeaconResponse common.SignedBeaconResponse
	)
	if m.cfg.spec.SlotToEpoch(slot) >= m.cfg.spec.DENEB_FORK_EPOCH {
		signedBeaconResponse = &deneb.SignedBeaconResponse{}
	} else if m.cfg.spec.SlotToEpoch(slot) >= m.cfg.spec.CAPELLA_FORK_EPOCH {
		signedBeaconResponse = &capella.SignedBeaconResponse{}
	} else if m.cfg.spec.SlotToEpoch(slot) >= m.cfg.spec.BELLATRIX_FORK_EPOCH {
		signedBeaconResponse = &bellatrix.SignedBeaconResponse{}
	} else {
		logrus.WithFields(logrus.Fields{
			"builder_id": m.cfg.id,
			"err":        fmt.Errorf("received signed beacon blinded block of unknown fork"),
		}).Error("Invalid slot requested")
		http.Error(
			w,
			"Unable to respond to header request",
			http.StatusBadRequest,
		)
		return
	}
	// Unmarshall the full signed beacon block
	if err := json.Unmarshal(requestBytes, &signedBeaconResponse); err != nil {
		logrus.WithFields(logrus.Fields{
			"builder_id": m.cfg.id,
			"err":        err,
			"request":    string(requestBytes),
		}).Error("Unable to parse request body")
		http.Error(w, "Unable to parse request body", http.StatusBadRequest)
		return
	}

	// Look up the payload in the history of bids
	builtBid, ok := m.builtPayloads[slot]
	if !ok {
		logrus.WithFields(logrus.Fields{
			"builder_id": m.cfg.id,
			"slot":       slot,
			"request":    string(requestBytes),
		}).Error("Could not find payload in history")
		http.Error(w, "Unable to get payload", http.StatusInternalServerError)
		return
	}

	// Record the signed beacon block
	signedBeaconBlockRoot := signedBeaconResponse.Root(m.cfg.spec)
	m.signedBeaconBlockMutex.Lock()
	m.signedBeaconBlock[signedBeaconBlockRoot] = true
	m.signedBeaconBlockMutex.Unlock()
	m.receivedSignedBeaconBlocksMutex.Lock()
	m.receivedSignedBeaconBlocks[signedBeaconResponse.Slot()] = signedBeaconResponse
	m.receivedSignedBeaconBlocksMutex.Unlock()

	// Obtain the public key used to validate the signed beacon response
	pubkey, ok := m.validatorPublicKeys[signedBeaconResponse.Slot()]
	if pubkey == nil || !ok {
		logrus.WithFields(logrus.Fields{
			"builder_id": m.cfg.id,
			"slot":       slot,
		}).Error("Could not find public key in history")
		http.Error(
			w,
			"Unable to validate signature",
			http.StatusInternalServerError,
		)
		return
	}
	pk, err := pubkey.Pubkey()
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"builder_id": m.cfg.id,
			"slot":       slot,
		}).Error("Could not convert public key")
		http.Error(
			w,
			"Unable to validate signature",
			http.StatusInternalServerError,
		)
		return
	}

	unblindedResponse, err := builtBid.ValidateReveal(
		pk, signedBeaconResponse, m.cfg.spec, slot, m.cl.Config.GenesisValidatorsRoot,
	)
	if err != nil {
		m.validationErrorsMutex.Lock()
		m.validationErrors[signedBeaconResponse.Slot()] = err
		m.validationErrorsMutex.Unlock()
		logrus.WithFields(logrus.Fields{
			"builder_id": m.cfg.id,
			"slot":       slot,
			"request":    string(requestBytes),
			"err":        err,
		}).Error("Error validating signed beacon response")
		http.Error(
			w,
			"Error validating signed beacon response",
			http.StatusInternalServerError,
		)
		return
	}

	logrus.WithFields(logrus.Fields{
		"builder_id": m.cfg.id,
		"root":       signedBeaconResponse.Root(m.cfg.spec).String(),
		"stateRoot":  signedBeaconResponse.StateRoot().String(),
		"slot":       signedBeaconResponse.Slot().String(),
		"publicKey":  pubkey.String(),
		"signature":  signedBeaconResponse.BlockSignature().String(),
	}).Info("Received signed beacon block")

	logrus.WithFields(logrus.Fields{
		"builder_id": m.cfg.id,
		"payload":    builtBid.FullPayload().GetBlockHash().String(),
	}).Info("Unblinded payload sent to CL")

	// Check if we are supposed to simulate an error
	m.cfg.mutex.Lock()
	errOnPayloadReveal := m.cfg.errorOnPayloadReveal
	m.cfg.mutex.Unlock()
	if errOnPayloadReveal != nil {
		if err := errOnPayloadReveal(slot); err != nil {
			logrus.WithFields(logrus.Fields{
				"builder_id": m.cfg.id,
				"slot":       slot,
				"err":        err,
			}).Error("Simulated error")
			http.Error(
				w,
				"Unable to respond to header request",
				http.StatusInternalServerError,
			)
			return
		}
	}

	if err := serveJSON(w, unblindedResponse); err != nil {
		logrus.WithFields(logrus.Fields{
			"builder_id": m.cfg.id,
			"err":        err,
		}).Error("Error preparing response from payload")
		http.Error(
			w,
			"Unable to respond to header request",
			http.StatusInternalServerError,
		)
		return
	}
}

func (m *MockBuilder) HandleStatus(
	w http.ResponseWriter, req *http.Request,
) {
	logrus.WithFields(logrus.Fields{
		"builder_id": m.cfg.id,
	}).Info(
		"Received request for status",
	)
	w.WriteHeader(http.StatusOK)
}

// mock builder options handlers
func (m *MockBuilder) parseSlotEpochRequest(
	vars map[string]string,
) (slot beacon.Slot, errcode int, err error) {
	if slotStr, ok := vars["slot"]; ok {
		var slotInt uint64
		if slotInt, err = strconv.ParseUint(slotStr, 10, 64); err != nil {
			errcode = http.StatusBadRequest
			return
		} else {
			slot = beacon.Slot(slotInt)
		}
	} else if epochStr, ok := vars["epoch"]; ok {
		var epoch uint64
		if epoch, err = strconv.ParseUint(epochStr, 10, 64); err != nil {
			errcode = http.StatusBadRequest
			return
		} else {
			if m.cfg.spec == nil {
				err = fmt.Errorf("unable to respond: spec not ready")
				errcode = http.StatusInternalServerError
				return
			}
			slot, err = m.cfg.spec.EpochStartSlot(beacon.Epoch(epoch))
			if err != nil {
				errcode = http.StatusInternalServerError
				return
			}
		}
	}
	return
}

func (m *MockBuilder) HandleMockDisableErrorOnHeaderRequest(
	w http.ResponseWriter, req *http.Request,
) {
	logrus.WithFields(logrus.Fields{
		"builder_id": m.cfg.id,
	}).Info(
		"Received request to disable error on payload request",
	)

	m.cfg.mutex.Lock()
	defer m.cfg.mutex.Unlock()
	m.cfg.errorOnHeaderRequest = nil

	w.WriteHeader(http.StatusOK)
}

func (m *MockBuilder) HandleMockEnableErrorOnHeaderRequest(
	w http.ResponseWriter, req *http.Request,
) {
	var (
		vars = mux.Vars(req)
	)

	slot, code, err := m.parseSlotEpochRequest(vars)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"builder_id": m.cfg.id,
			"err":        err,
		}).Error("Unable to parse slot/epoch in request")
		http.Error(
			w,
			fmt.Sprintf("Unable to respond request: %v", err),
			code,
		)
		return
	}

	logrus.WithFields(logrus.Fields{
		"builder_id": m.cfg.id,
		"slot":       slot,
	}).Info(
		"Received request to enable error on payload request",
	)

	if err = WithErrorOnHeaderRequestAtSlot(slot).apply(m); err != nil {
		logrus.WithFields(logrus.Fields{
			"builder_id": m.cfg.id,
			"err":        err,
		}).Error("Unable to respond request")
		http.Error(
			w,
			fmt.Sprintf("Unable to respond request: %v", err),
			code,
		)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (m *MockBuilder) HandleMockDisableErrorOnPayloadReveal(
	w http.ResponseWriter, req *http.Request,
) {
	logrus.WithFields(logrus.Fields{
		"builder_id": m.cfg.id,
	}).Info(
		"Received request to disable error on payload reveal",
	)

	m.cfg.mutex.Lock()
	defer m.cfg.mutex.Unlock()
	m.cfg.errorOnPayloadReveal = nil

	w.WriteHeader(http.StatusOK)
}

func (m *MockBuilder) HandleMockEnableErrorOnPayloadReveal(
	w http.ResponseWriter, req *http.Request,
) {
	var (
		vars = mux.Vars(req)
	)

	slot, code, err := m.parseSlotEpochRequest(vars)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"builder_id": m.cfg.id,
			"err":        err,
		}).Error("Unable to parse slot/epoch in request")
		http.Error(
			w,
			fmt.Sprintf("Unable to respond request: %v", err),
			code,
		)
		return
	}

	logrus.WithFields(logrus.Fields{
		"builder_id": m.cfg.id,
		"slot":       slot,
	}).Info(
		"Received request to enable error on payload reveal",
	)

	if err = WithErrorOnPayloadRevealAtSlot(slot).apply(m); err != nil {
		logrus.WithFields(logrus.Fields{
			"builder_id": m.cfg.id,
			"err":        err,
		}).Error("Unable to respond request")
		http.Error(
			w,
			fmt.Sprintf("Unable to respond request: %v", err),
			code,
		)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (m *MockBuilder) HandleMockDisableInvalidatePayloadAttributes(
	w http.ResponseWriter, req *http.Request,
) {
	logrus.WithFields(logrus.Fields{
		"builder_id": m.cfg.id,
	}).Info(
		"Received request to disable invalidation of payload attributes",
	)

	m.cfg.mutex.Lock()
	defer m.cfg.mutex.Unlock()
	m.cfg.payloadAttrModifier = nil

	w.WriteHeader(http.StatusOK)
}

func (m *MockBuilder) HandleMockEnableInvalidatePayloadAttributes(
	w http.ResponseWriter, req *http.Request,
) {
	var (
		vars   = mux.Vars(req)
		invTyp PayloadAttributesInvalidation
	)

	slot, code, err := m.parseSlotEpochRequest(vars)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"builder_id": m.cfg.id,
			"err":        err,
		}).Error("Unable to parse slot/epoch in request")
		http.Error(
			w,
			fmt.Sprintf("Unable to respond request: %v", err),
			code,
		)
		return
	}

	if typeStr, ok := vars["type"]; !ok {
		logrus.WithFields(logrus.Fields{
			"builder_id": m.cfg.id,
		}).Error("Unable to parse request url: missing type var")
		http.Error(
			w,
			"Unable to parse request url: missing type var",
			http.StatusBadRequest,
		)
		return
	} else if invTyp, ok = PayloadAttrInvalidationTypes[typeStr]; !ok {
		logrus.WithFields(logrus.Fields{
			"builder_id": m.cfg.id,
			"type":       typeStr,
		}).Error("Unable to parse request url: unknown invalidity type")
		http.Error(
			w,
			fmt.Sprintf("Unable to parse request url: unknown invalidity type: %s", typeStr),
			http.StatusBadRequest,
		)
		return
	}

	logrus.WithFields(logrus.Fields{
		"builder_id": m.cfg.id,
		"type":       invTyp,
		"slot":       slot,
	}).Info(
		"Received request to enable payload attributes invalidation",
	)

	if err = WithPayloadAttributesInvalidatorAtSlot(slot, invTyp).apply(m); err != nil {
		logrus.WithFields(logrus.Fields{
			"builder_id": m.cfg.id,
			"err":        err,
		}).Error("Unable to enable payload attr invalidation")
		http.Error(
			w,
			"Unable to enable payload attr invalidation",
			http.StatusInternalServerError,
		)
		return
	}

	w.WriteHeader(http.StatusOK)
}

func (m *MockBuilder) HandleMockDisableInvalidatePayload(
	w http.ResponseWriter, req *http.Request,
) {
	logrus.WithFields(logrus.Fields{
		"builder_id": m.cfg.id,
	}).Info(
		"Received request to disable invalidation of payload",
	)

	m.cfg.mutex.Lock()
	defer m.cfg.mutex.Unlock()
	m.cfg.payloadModifier = nil

	w.WriteHeader(http.StatusOK)
}

func (m *MockBuilder) HandleMockEnableInvalidatePayload(
	w http.ResponseWriter, req *http.Request,
) {
	var (
		vars   = mux.Vars(req)
		invTyp PayloadInvalidation
	)

	slot, code, err := m.parseSlotEpochRequest(vars)
	if err != nil {
		logrus.WithFields(logrus.Fields{
			"builder_id": m.cfg.id,
			"err":        err,
		}).Error("Unable to parse slot/epoch in request")
		http.Error(
			w,
			fmt.Sprintf("Unable to respond request: %v", err),
			code,
		)
		return
	}

	if typeStr, ok := vars["type"]; !ok {
		logrus.WithFields(logrus.Fields{
			"builder_id": m.cfg.id,
		}).Error("Unable to parse request url: missing type var")
		http.Error(
			w,
			"Unable to parse request url: missing type var",
			http.StatusBadRequest,
		)
		return
	} else if invTyp, ok = PayloadInvalidationTypes[typeStr]; !ok {
		logrus.WithFields(logrus.Fields{
			"builder_id": m.cfg.id,
			"type":       typeStr,
		}).Error("Unable to parse request url: unknown invalidity type")
		http.Error(
			w,
			fmt.Sprintf("Unable to parse request url: unknown invalidity type: %s", typeStr),
			http.StatusBadRequest,
		)
		return
	}

	logrus.WithFields(logrus.Fields{
		"builder_id": m.cfg.id,
		"type":       invTyp,
		"slot":       slot,
	}).Info(
		"Received request to enable payload attributes invalidation",
	)

	if err = WithPayloadInvalidatorAtSlot(slot, invTyp).apply(m); err != nil {
		logrus.WithFields(logrus.Fields{
			"builder_id": m.cfg.id,
			"err":        err,
		}).Error("Unable to enable payload attr invalidation")
		http.Error(
			w,
			"Unable to enable payload attr invalidation",
			http.StatusInternalServerError,
		)
		return
	}

	w.WriteHeader(http.StatusOK)
}

// Stats handlers

func (m *MockBuilder) HandleValidationErrors(
	w http.ResponseWriter, req *http.Request,
) {
	// Return the map of validation errors
	m.validationErrorsMutex.Lock()
	defer m.validationErrorsMutex.Unlock()
	validationErrors := make(map[string]string)
	for k, v := range m.validationErrors {
		validationErrors[k.String()] = v.Error()
	}
	if err := serveJSON(w, validationErrors); err != nil {
		logrus.WithFields(logrus.Fields{
			"builder_id": m.cfg.id,
			"err":        err,
		}).Error("Error writing JSON response to CL")
		http.Error(
			w,
			"Unable to respond to header request",
			http.StatusInternalServerError,
		)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// helpers

func serveJSON(w http.ResponseWriter, value interface{}) error {
	resp, err := json.Marshal(value)
	if err != nil {
		return err
	}
	logrus.Debug(string(resp))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	n, err := w.Write(resp)
	if err != nil {
		panic(err)
	}
	logrus.Debugf("Wrote %d bytes on response", n)
	if logrus.GetLevel() >= logrus.DebugLevel {
		fields := logrus.Fields{}
		for k, v := range w.Header() {
			fields[k] = v
		}
		logrus.WithFields(fields).Debug("Response headers")
	}
	return nil
}

func ModifyExtraData(p *api.ExecutableData, versionedHashes []el_common.Hash, beaconRoot *el_common.Hash, newExtraData []byte) error {
	if p == nil {
		return fmt.Errorf("nil payload")
	}
	if b, err := api.ExecutableDataToBlock(*p, versionedHashes, beaconRoot); err != nil {
		return err
	} else {
		h := b.Header()
		h.Extra = newExtraData
		p.ExtraData = newExtraData
		p.BlockHash = h.Hash()
	}
	return nil
}

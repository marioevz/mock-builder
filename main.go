// Mock builder as an stand-alone program
package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"math/big"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"time"

	"github.com/marioevz/eth-clients/clients"
	beacon_client "github.com/marioevz/eth-clients/clients/beacon"
	exec_client "github.com/marioevz/eth-clients/clients/execution"
	mock_builder "github.com/marioevz/mock-builder/mock"
	beacon "github.com/protolambda/zrnt/eth2/beacon/common"
	"github.com/sirupsen/logrus"
)

type Logger struct {
	*logrus.Logger
}

func (l *Logger) Logf(format string, values ...interface{}) {
	l.Logger.Logf(0, format, values...)
}

func parseForkOrEpoch(
	forkepoch string,
	spec *beacon.Spec,
) (beacon.Epoch, error) {
	if n, err := strconv.ParseUint(forkepoch, 10, 64); err == nil {
		return beacon.Epoch(n), nil
	} else {
		switch forkepoch {
		case "bellatrix":
			return spec.BELLATRIX_FORK_EPOCH, nil
		case "capella":
			return spec.CAPELLA_FORK_EPOCH, nil
		case "deneb":
			return spec.DENEB_FORK_EPOCH, nil
		}
	}
	return beacon.Epoch(0), fmt.Errorf("unable to parse: %s", forkepoch)
}

func parseInvParamString(
	paramStr string,
	spec *beacon.Spec,
) (beacon.Epoch, string, error) {
	split := strings.Split(paramStr, ",")
	if len(split) != 2 {
		return 0, "", fmt.Errorf("bad format")
	}
	var (
		epochStr   = split[0]
		invTypeStr = split[1]
	)
	epoch, err := parseForkOrEpoch(epochStr, spec)
	if err != nil {
		return 0, "", err
	}
	return epoch, invTypeStr, nil
}

func main() {
	var (
		el                       *exec_client.ExecutionClient
		bn                       *beacon_client.BeaconClient
		logger                   = &Logger{logrus.New()}
		clEndpoint               string
		elEndpoint               string
		specPath                 string
		jwtSecret                string
		invPayload               string
		invPayloadAttr           string
		extraDataWatermark       string
		clientInitTimeoutSeconds int
		ttd                      int
		port                     int
		bidmult                  int
		options                  = make([]mock_builder.Option, 0)
	)

	flag.StringVar(
		&clEndpoint,
		"cl",
		"",
		"REST API endpoint of the consensus client to use: <IP>:<PORT>",
	)
	flag.StringVar(
		&elEndpoint,
		"el",
		"",
		"RPC endpoint of the execution client to use: <IP>:<PORT>",
	)
	flag.StringVar(
		&specPath,
		"beacon-spec",
		"",
		"The path and filename to the source config.yaml (default requested from the beacon API)",
	)
	flag.StringVar(
		&jwtSecret,
		"jwt-secret",
		"0x7365637265747365637265747365637265747365637265747365637265747365",
		"jwt secret value as hexadecimal string, used to communicate to the execution client",
	)
	flag.StringVar(
		&invPayload,
		"invalidate-payload",
		"",
		"Invalidate a payload by modifying one of its fields, starting from the specified fork (bellatrix, capella, deneb) or epoch number: <FORK/EPOCH NUMBER>,<INVALIDATION TYPE>\nInvalidation types:\n"+strings.Join(
			mock_builder.PayloadInvalidationTypeNames(),
			"\n",
		),
	)
	flag.StringVar(
		&invPayloadAttr,
		"invalidate-payload-attributes",
		"",
		"Invalidate a payload by modifying the payload attributes sent to the execution client, starting from the specified fork (bellatrix, capella, deneb) or epoch number: <FORK/EPOCH NUMBER>,<INVALIDATION TYPE>\nInvalidation types:\n"+strings.Join(
			mock_builder.PayloadAttrInvalidationTypeNames(),
			",",
		),
	)
	flag.StringVar(
		&extraDataWatermark,
		"extra-data",
		"builder payload",
		"extra data string appended to every built payload by the builder",
	)
	flag.IntVar(
		&clientInitTimeoutSeconds,
		"client-init-timeout",
		60,
		"clients initialization wait timeout in seconds",
	)
	flag.IntVar(
		&ttd,
		"ttd",
		0,
		"chain configured terminal total difficulty (default 0)",
	)
	flag.IntVar(
		&port,
		"port",
		mock_builder.DEFAULT_BUILDER_PORT,
		"port used to listen for the RESTful interface",
	)
	flag.IntVar(
		&bidmult,
		"bid-multiplier",
		0,
		"multiply the bid wei value by this integer",
	)

	flag.CommandLine.Parse(os.Args[1:])

	if clEndpoint == "" {
		fatalf("Missing required consensus client endpoint")
	}

	if elEndpoint == "" {
		fatalf("Missing required consensus client endpoint")
	}

	options = append(options, mock_builder.WithPort(port))

	// Configure an external CL
	externalCl, err := clients.ExternalClientFromURL(clEndpoint, "cl")
	if err != nil {
		fatalf(
			"error parsing consensus client url (%s): %v\n",
			clEndpoint,
			err,
		)
	}

	beaconCfg := beacon_client.BeaconClientConfig{
		BeaconAPIPort: externalCl.Port,
	}
	bn = &beacon_client.BeaconClient{
		Client: externalCl,
		Logger: logger,
		Config: beaconCfg,
	}

	if specPath != "" {
		// TODO: Load spec config from yaml file
		// fatalf("Missing beacon-spec config.yaml file")
	}

	initctx, cancel := context.WithTimeout(
		context.Background(),
		time.Second*time.Duration(clientInitTimeoutSeconds),
	)
	defer cancel()
	if err := bn.Init(initctx); err != nil {
		if initctx.Err() != nil {
			fatalf(
				"error initializing consensus client: %d second init timeout exceeded\n",
				clientInitTimeoutSeconds,
			)
		}
		fatalf(
			"error initializing consensus client: %v\n",
			err,
		)
	}
	// We certainly have the beacon client config now, add it to the mock builder
	options = append(
		options,
		mock_builder.WithBeaconGenesisTime(*bn.Config.GenesisTime),
	)
	options = append(options, mock_builder.WithSpec(bn.Config.Spec))
	if bidmult > 1 {
		options = append(
			options,
			mock_builder.WithPayloadWeiValueMultiplier(
				big.NewInt(int64(bidmult)),
			),
		)
	}
	if extraDataWatermark != "" {
		options = append(
			options,
			mock_builder.WithExtraDataWatermark(extraDataWatermark),
		)
	}

	// Check if we need to produce an invalidation
	if invPayload != "" {
		if epoch, invTypeStr, err := parseInvParamString(invPayload, bn.Config.Spec); err != nil {
			fatalf(
				"unable to parse payload invalidation fork/epoch,type: %s",
				invPayload,
			)
		} else {
			if invType, ok := mock_builder.PayloadInvalidationTypes[invTypeStr]; !ok {
				fatalf(
					"unknown payload invalidation type: %s",
					invTypeStr,
				)
			} else {
				options = append(options, mock_builder.WithPayloadInvalidatorAtEpoch(epoch, invType))

			}
		}
	}

	if invPayloadAttr != "" {
		if epoch, invAttrTypeStr, err := parseInvParamString(invPayloadAttr, bn.Config.Spec); err != nil {
			fatalf(
				"unable to parse payload attr invalidation fork/epoch,type: %s",
				invPayload,
			)
		} else {
			if invType, ok := mock_builder.PayloadAttrInvalidationTypes[invAttrTypeStr]; !ok {
				fatalf(
					"unknown payload attr invalidation type: %s",
					invAttrTypeStr,
				)
			} else {
				options = append(options, mock_builder.WithPayloadAttributesInvalidatorAtEpoch(epoch, invType))

			}
		}
	}

	// Configure an external EL
	externalEl, err := clients.ExternalClientFromURL(elEndpoint, "el")
	if err != nil {
		fatalf("error parsing execution client url: %v\n", err)
	}

	jwtSecretBytes, err := hex.DecodeString(
		strings.TrimPrefix(jwtSecret, "0x"),
	)
	if err != nil {
		fatalf("error parsing jwt secret hex: %v\n", err)
	}
	executionCfg := exec_client.ExecutionClientConfig{
		TerminalTotalDifficulty: int64(ttd),
		JWTSecret:               jwtSecretBytes,
		EngineAPIPort:           externalEl.GetPort(),
	}
	el = &exec_client.ExecutionClient{
		Client: externalEl,
		Logger: logger,
		Config: executionCfg,
	}
	initctx, cancel = context.WithTimeout(
		context.Background(),
		time.Second*time.Duration(clientInitTimeoutSeconds),
	)
	defer cancel()
	if err := el.Init(initctx); err != nil {
		if initctx.Err() != nil {
			fatalf(
				"error initializing execution client: %d second init timeout exceeded\n",
				clientInitTimeoutSeconds,
			)
		}
		fatalf(
			"error initializing execution client: %v\n",
			err,
		)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	_, err = mock_builder.NewMockBuilder(ctx, el, bn, options...)
	if err != nil {
		fatalf("unable to start mock builder: %v\n", err)
	}

	// terminate on SIGINT
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	<-c

}

func fatalf(format string, args ...interface{}) {
	fatal(fmt.Errorf(format, args...))
}

func fatal(err error) {
	flag.CommandLine.Usage()
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

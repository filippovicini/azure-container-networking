// Copyright 2017 Microsoft. All rights reserved.
// MIT License

package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/Azure/azure-container-networking/cni"
	"github.com/Azure/azure-container-networking/cni/api"
	zaplog "github.com/Azure/azure-container-networking/cni/log"
	"github.com/Azure/azure-container-networking/cni/network"
	"github.com/Azure/azure-container-networking/common"
	"github.com/Azure/azure-container-networking/nns"
	"github.com/Azure/azure-container-networking/platform"
	"github.com/Azure/azure-container-networking/telemetry"
	"github.com/pkg/errors"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/jaeger"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	"go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.24.0"
	"go.uber.org/zap"
)

const (
	ipamQueryURL                    = "http://168.63.129.16/machine/plugins?comp=nmagent&type=getinterfaceinfov1"
	pluginName                      = "CNI"
	telemetryNumRetries             = 5
	telemetryWaitTimeInMilliseconds = 200
	name                            = "azure-vnet"
)

// Version is populated by make during build.
var version string

var logger = zaplog.CNILogger.With(zap.String("component", "cni-main"))

// Command line arguments for CNI plugin.
var args = common.ArgumentList{
	{
		Name:         common.OptVersion,
		Shorthand:    common.OptVersionAlias,
		Description:  "Print version information",
		Type:         "bool",
		DefaultValue: false,
	},
}

// Prints version information.
func printVersion() {
	fmt.Printf("Azure CNI Version %v\n", version)
}

func initOpenTelemetry(ctx context.Context, serviceName string) (*trace.TracerProvider, error) {
	// Get Jaeger endpoint from environment variable, default to your Jaeger VM
	jaegerEndpoint := os.Getenv("JAEGER_ENDPOINT")
	if jaegerEndpoint == "" {
		jaegerEndpoint = "http://135.18.41.175:14268/api/traces"
	}

	logger.Info("Initializing OpenTelemetry", zap.String("jaegerEndpoint", jaegerEndpoint))

	// Create Jaeger exporter
	exporter, err := jaeger.New(jaeger.WithCollectorEndpoint(
		jaeger.WithEndpoint(jaegerEndpoint),
	))
	if err != nil {
		return nil, fmt.Errorf("failed to create Jaeger exporter: %w", err)
	}

	// Create resource
	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceNameKey.String(serviceName),
			semconv.ServiceVersionKey.String(version),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}

	tp := trace.NewTracerProvider(
		trace.WithBatcher(exporter),
		trace.WithResource(res),
		trace.WithSampler(trace.AlwaysSample()),
	)

	otel.SetTracerProvider(tp)

	otel.SetTextMapPropagator(propagation.TraceContext{})

	logger.Info("OpenTelemetry initialized", zap.String("endpoint", jaegerEndpoint))
	return tp, nil
}

func rootExecute() error {
	var config common.PluginConfig

	config.Version = version

	reportManager := &telemetry.ReportManager{
		Report: &telemetry.CNIReport{
			Context:       "AzureCNI",
			SystemDetails: telemetry.SystemInfo{},
			Version:       version,
			Logger:        logger,
		},
	}

	cniReport := reportManager.Report.(*telemetry.CNIReport)

	netPlugin, err := network.NewPlugin(
		name,
		&config,
		&nns.GrpcClient{},
		&network.Multitenancy{},
	)
	if err != nil {
		network.PrintCNIError(fmt.Sprintf("Failed to create network plugin, err:%v.\n", err))
		return errors.Wrap(err, "Create plugin error")
	}

	ctx := context.Background()
	ctx, span := otel.Tracer("azure-vnet").Start(ctx, "read env variable")
	defer span.End()
	// Starting point
	// Check CNI_COMMAND value
	cniCmd := os.Getenv(cni.Cmd)

	if cniCmd != cni.CmdVersion {
		logger.Info("Environment variable set", zap.String("CNI_COMMAND", cniCmd))

		cniReport.GetReport(pluginName, version, ipamQueryURL)

		var upTime time.Time
		p := platform.NewExecClient(logger)
		upTime, err = p.GetLastRebootTime()
		if err == nil {
			cniReport.VMUptime = upTime.Format("2006-01-02 15:04:05")
		}

		// CNI attempts to acquire lock
		if err = netPlugin.Plugin.InitializeKeyValueStore(&config); err != nil {
			// Error acquiring lock
			network.PrintCNIError(fmt.Sprintf("Failed to initialize key-value store of network plugin: %v", err))

			// Connect to telemetry service if it is running, otherwise skips telemetry
			telemetry.AIClient.ConnectTelemetry(logger)
			defer telemetry.AIClient.DisconnectTelemetry()

			if telemetry.AIClient.IsConnected() {
				telemetry.AIClient.SendError(err)
			} else {
				logger.Error("Not connected to telemetry service, skipping sending error to application insights")
			}
			return errors.Wrap(err, "lock acquire error")
		}

		defer func() {
			if errUninit := netPlugin.Plugin.UninitializeKeyValueStore(); errUninit != nil {
				logger.Error("Failed to uninitialize key-value store of network plugin", zap.Error(errUninit))
			}

			if recover() != nil {
				os.Exit(1)
			}
		}()
		// At this point, lock is acquired
		// Start telemetry process if not already started. This should be done inside lock, otherwise multiple process
		// end up creating/killing telemetry process results in undesired state.
		telemetry.AIClient.StartAndConnectTelemetry(logger)
		defer telemetry.AIClient.DisconnectTelemetry()
		telemetry.AIClient.SetSettings(cniReport)

		t := time.Now()
		cniReport.Timestamp = t.Format("2006-01-02 15:04:05")

		if err = netPlugin.Start(&config); err != nil {
			network.PrintCNIError(fmt.Sprintf("Failed to start network plugin, err:%v.\n", err))
			telemetry.AIClient.SendError(err)
			panic("network plugin start fatal error")
		}

		// used to dump state
		if cniCmd == cni.CmdGetEndpointsState {
			logger.Debug("Retrieving state")
			var simpleState *api.AzureCNIState
			simpleState, err = netPlugin.GetAllEndpointState("azure")
			if err != nil {
				logger.Error("Failed to get Azure CNI state", zap.Error(err))
				return errors.Wrap(err, "Get all endpoints error")
			}

			err = simpleState.PrintResult()
			if err != nil {
				logger.Error("Failed to print state result to stdout", zap.Error(err))
			}

			return errors.Wrap(err, "Get cni state printresult error")
		}
	}

	handled, _ := network.HandleIfCniUpdate(netPlugin.Update)
	if handled {
		logger.Info("CNI UPDATE finished.")
	} else if err = netPlugin.Execute(cni.PluginApi(netPlugin)); err != nil {
		logger.Error("Failed to execute network plugin", zap.Error(err))
	}

	if cniCmd == cni.CmdVersion {
		return errors.Wrap(err, "Execute netplugin failure")
	}
	netPlugin.Stop()

	return errors.Wrap(err, "Execute netplugin failure")
}

// Main is the entry point for CNI network plugin.
func main() {
	// Initialize and parse command line arguments.
	common.ParseArgs(&args, printVersion)
	vers := common.GetArg(common.OptVersion).(bool)

	if vers {
		printVersion()
		os.Exit(0)
	}

	// Initialize OpenTelemetry tracing
	ctx := context.Background()
	tp, err := initOpenTelemetry(ctx, name)
	if err != nil {
		logger.Error("Failed to initialize OpenTelemetry", zap.Error(err))
		// Continue without tracing rather than failing completely
	} else {
		// Ensure tracer provider is properly shutdown on exit
		defer func() {
			if shutdownErr := tp.Shutdown(context.Background()); shutdownErr != nil {
				logger.Error("Error shutting down tracer provider", zap.Error(shutdownErr))
			}
		}()
		logger.Info("OpenTelemetry tracing initialized successfully")
	}

	if rootExecute() != nil {
		os.Exit(1)
	}
}

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
	zapLog "github.com/Azure/azure-container-networking/cni/log"
	"github.com/Azure/azure-container-networking/cni/network"
	"github.com/Azure/azure-container-networking/common"
	"github.com/Azure/azure-container-networking/log"
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

var logger = zapLog.CNILogger.With(zap.String("component", "cni-main"))

const (
	ipamQueryURL = "http://168.63.129.16/machine/plugins?comp=nmagent&type=getinterfaceinfov1"
	pluginName   = "CNI"
	name         = "azure-vnet"
	stateless    = true
)

// Version is populated by make during build.
var version string

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

	log.SetName(name)
	log.SetLevel(log.LevelInfo)
	if err := log.SetTargetLogDirectory(log.TargetLogfile, ""); err != nil {
		fmt.Printf("Failed to setup cni logging: %v\n", err)
	}
	defer log.Close()

	config.Version = version
	config.Stateless = stateless

	reportManager := &telemetry.ReportManager{
		Report: &telemetry.CNIReport{
			Context:       "AzureCNI",
			SystemDetails: telemetry.SystemInfo{},
			Version:       version,
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

		defer func() {
			if recover() != nil {
				os.Exit(1)
			}
		}()

		// Connect to the telemetry process. Does not start the telemetry service if it is not running.
		telemetry.AIClient.ConnectTelemetry(logger)
		defer telemetry.AIClient.DisconnectTelemetry()
		telemetry.AIClient.SetSettings(cniReport)

		t := time.Now()
		cniReport.Timestamp = t.Format("2006-01-02 15:04:05")

		if err = netPlugin.Start(&config); err != nil {
			network.PrintCNIError(fmt.Sprintf("Failed to start network plugin, err:%v.\n", err))
			telemetry.AIClient.SendError(err)
			panic("network plugin start fatal error")
		}
	}
	// dump an empty state in case the API is called for StateMigration or InitilizeCNS from CNI State
	if cniCmd == cni.CmdGetEndpointsState {
		logger.Debug("returning an empty state")
		simpleState := api.AzureCNIState{
			ContainerInterfaces: make(map[string]api.PodNetworkInterfaceInfo),
		}
		err = simpleState.PrintResult()
		if err != nil {
			logger.Error("Failed to print state result to stdout", zap.Error(err))
		}

		return errors.Wrap(err, "Get cni state printresult error")
	}

	if cniCmd == cni.CmdVersion {
		return errors.Wrap(err, "Execute netplugin failure")
	}

	if err = netPlugin.Execute(cni.PluginApi(netPlugin)); err != nil {
		return errors.Wrap(err, "Failed to execute network plugin")
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

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
	"go.opentelemetry.io/otel/attribute"
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
	jaegerEndpoint := os.Getenv("JAEGER_ENDPOINT")
	if jaegerEndpoint == "" {
		jaegerEndpoint = "http://10.0.0.4:14268/api/traces"
	}

	logger.Info("Initializing OpenTelemetry with Jaeger exporter", zap.String("jaegerEndpoint", jaegerEndpoint))

	// Create Jaeger exporter
	exporter, err := jaeger.New(jaeger.WithCollectorEndpoint(
		jaeger.WithEndpoint(jaegerEndpoint),
	))
	if err != nil {
		logger.Error("Failed to create Jaeger exporter", zap.Error(err), zap.String("endpoint", jaegerEndpoint))
		return nil, fmt.Errorf("failed to create Jaeger exporter: %w", err)
	}

	// Create resource with additional attributes
	res, err := resource.New(ctx,
		resource.WithAttributes(
			semconv.ServiceNameKey.String(serviceName),
			semconv.ServiceVersionKey.String(version),
			semconv.ServiceInstanceIDKey.String(fmt.Sprintf("%s-%d", serviceName, os.Getpid())),
		),
	)
	if err != nil {
		logger.Error("Failed to create resource", zap.Error(err))
		return nil, fmt.Errorf("failed to create resource: %w", err)
	}

	tp := trace.NewTracerProvider(
		trace.WithBatcher(exporter,
			trace.WithBatchTimeout(time.Second*2),
			trace.WithExportTimeout(time.Second*30),
		),
		trace.WithResource(res),
		trace.WithSampler(trace.AlwaysSample()),
	)

	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.TraceContext{})

	logger.Info("OpenTelemetry initialized successfully",
		zap.String("endpoint", jaegerEndpoint),
		zap.String("serviceName", serviceName),
		zap.String("version", version))

	// Test span creation and export
	tracer := tp.Tracer("test-tracer")
	_, testSpan := tracer.Start(ctx, "initialization-test")
	testSpan.SetAttributes(
		semconv.ServiceNameKey.String(serviceName),
		semconv.ServiceVersionKey.String(version),
	)
	testSpan.End()

	// Force flush to ensure test span is exported
	flushCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	if err := tp.ForceFlush(flushCtx); err != nil {
		logger.Warn("Failed to flush test span", zap.Error(err))
	} else {
		logger.Info("Test span created and flushed successfully")
	}

	return tp, nil
}

func rootExecute(ctx context.Context) error {
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

	ctx, span := otel.Tracer("cni").Start(ctx, "cni-execution")
	defer span.End()

	// Starting point
	// Check CNI_COMMAND value
	cniCmd := os.Getenv(cni.Cmd)

	if cniCmd != cni.CmdVersion {
		logger.Info("Environment variable set", zap.String("CNI_COMMAND", cniCmd))
		span.SetAttributes(
			attribute.String("cni.command", cniCmd),
			attribute.String("service.name", name),
		)
		span.AddEvent("CNI command processing started")

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
			span.RecordError(err)
			span.AddEvent("Network plugin start failed")
			network.PrintCNIError(fmt.Sprintf("Failed to start network plugin, err:%v.\n", err))
			telemetry.AIClient.SendError(err)
			panic("network plugin start fatal error")
		}
		span.AddEvent("Network plugin started successfully")

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
		span.AddEvent("CNI update handled")
	} else {
		span.AddEvent("Executing CNI plugin")
		if err = netPlugin.Execute(cni.PluginApi(netPlugin)); err != nil {
			span.RecordError(err)
			span.AddEvent("CNI plugin execution failed")
			logger.Error("Failed to execute network plugin", zap.Error(err))
		} else {
			span.AddEvent("CNI plugin execution completed successfully")
		}
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
			logger.Info("Shutting down OpenTelemetry tracer provider")
			// Force flush before shutdown to ensure all spans are exported
			flushCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			if flushErr := tp.ForceFlush(flushCtx); flushErr != nil {
				logger.Error("Error flushing tracer provider", zap.Error(flushErr))
			} else {
				logger.Info("Successfully flushed tracer provider")
			}

			// Now shutdown
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer shutdownCancel()

			if shutdownErr := tp.Shutdown(shutdownCtx); shutdownErr != nil {
				logger.Error("Error shutting down tracer provider", zap.Error(shutdownErr))
			} else {
				logger.Info("Successfully shut down tracer provider")
			}
		}()
		logger.Info("OpenTelemetry tracing initialized successfully")
	}

	ctx, span := otel.Tracer("azure-cni").Start(ctx, "main-execution")
	defer func() {
		span.End()
		// Force flush this span immediately to ensure it reaches Jaeger
		if tp != nil {
			flushCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if err := tp.ForceFlush(flushCtx); err != nil {
				logger.Error("Failed to flush main execution span", zap.Error(err))
			}
		}
	}()
	logger.Info("azure trace initialized")
	logger.Info("TraceID", zap.String("traceID", span.SpanContext().TraceID().String()))
	logger.Info("SpanID", zap.String("spanID", span.SpanContext().SpanID().String()))

	if err := rootExecute(ctx); err != nil {
		span.RecordError(err)
		span.SetAttributes(
			semconv.ServiceNameKey.String(name),
			semconv.ServiceVersionKey.String(version),
		)
		logger.Error("Root execution failed", zap.Error(err))

		// Force flush immediately to capture the error span
		if tp != nil {
			flushCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if flushErr := tp.ForceFlush(flushCtx); flushErr != nil {
				logger.Error("Failed to flush error span", zap.Error(flushErr))
			} else {
				logger.Info("Successfully flushed error span to Jaeger")
			}
		}

		os.Exit(1)
	}
}

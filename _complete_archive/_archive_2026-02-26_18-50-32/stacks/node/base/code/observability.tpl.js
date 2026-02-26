/*
File: observability.tpl.js
Purpose: OpenTelemetry tracing setup for Node.js
Generated for: {{PROJECT_NAME}}
*/

const { NodeSDK } = require('@opentelemetry/sdk-node');
const { getNodeAutoInstrumentations } = require('@opentelemetry/auto-instrumentations-node');
const { OTLPTraceExporter } = require('@opentelemetry/exporter-trace-otlp-grpc');
const { Resource } = require('@opentelemetry/resources');
const { SemanticResourceAttributes } = require('@opentelemetry/semantic-conventions');
const { trace, SpanStatusCode } = require('@opentelemetry/api');

let sdk;

function setupTelemetry(serviceName, otlpEndpoint = 'http://localhost:4317') {
    const exporter = new OTLPTraceExporter({
        url: otlpEndpoint,
    });

    sdk = new NodeSDK({
        resource: new Resource({
            [SemanticResourceAttributes.SERVICE_NAME]: serviceName,
        }),
        traceExporter: exporter,
        instrumentations: [getNodeAutoInstrumentations()],
    });

    sdk.start();

    process.on('SIGTERM', () => {
        sdk.shutdown()
            .then(() => console.log('Tracing terminated'))
            .catch((error) => console.error('Error terminating tracing', error))
            .finally(() => process.exit(0));
    });

    return trace.getTracer(serviceName);
}

function getTracer(name) {
    return trace.getTracer(name);
}

// Manual span creation helper
async function withSpan(name, fn, attributes = {}) {
    const tracer = trace.getTracer('default');
    return tracer.startActiveSpan(name, async (span) => {
        try {
            Object.entries(attributes).forEach(([key, value]) => {
                span.setAttribute(key, value);
            });
            const result = await fn();
            span.setStatus({ code: SpanStatusCode.OK });
            return result;
        } catch (error) {
            span.setStatus({ code: SpanStatusCode.ERROR, message: error.message });
            span.recordException(error);
            throw error;
        } finally {
            span.end();
        }
    });
}

module.exports = {
    setupTelemetry,
    getTracer,
    withSpan,
};

// Usage:
// const { setupTelemetry, withSpan } = require('./observability');
// setupTelemetry('my-service');
// await withSpan('database-query', async () => { ... });

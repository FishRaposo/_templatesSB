"""
File: observability.tpl.py
Purpose: OpenTelemetry tracing setup
Generated for: {{PROJECT_NAME}}
"""

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource, SERVICE_NAME
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.requests import RequestsInstrumentor
from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor

def setup_telemetry(service_name: str, otlp_endpoint: str = "http://localhost:4317"):
    """Initialize OpenTelemetry tracing"""
    
    resource = Resource.create({SERVICE_NAME: service_name})
    
    provider = TracerProvider(resource=resource)
    
    otlp_exporter = OTLPSpanExporter(endpoint=otlp_endpoint, insecure=True)
    processor = BatchSpanProcessor(otlp_exporter)
    provider.add_span_processor(processor)
    
    trace.set_tracer_provider(provider)
    
    # Auto-instrument common libraries
    RequestsInstrumentor().instrument()
    
    return trace.get_tracer(service_name)

def instrument_fastapi(app):
    """Instrument FastAPI application"""
    FastAPIInstrumentor.instrument_app(app)

def instrument_sqlalchemy(engine):
    """Instrument SQLAlchemy engine"""
    SQLAlchemyInstrumentor().instrument(engine=engine)

# Manual tracing example
def example_tracing():
    tracer = trace.get_tracer(__name__)
    
    with tracer.start_as_current_span("parent-operation") as span:
        span.set_attribute("user.id", "123")
        
        with tracer.start_as_current_span("child-operation"):
            # Do work here
            pass

# Usage:
# tracer = setup_telemetry("my-service")
# instrument_fastapi(app)

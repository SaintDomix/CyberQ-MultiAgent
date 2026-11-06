"""Additive, offline web telemetry normalization; no training or network discovery."""
from .schema import CanonicalWebEvent, NormalizedBatch, SCHEMA_VERSION
from .ingest import ingest
from .adapters import adapter

__all__ = ['CanonicalWebEvent', 'NormalizedBatch', 'SCHEMA_VERSION', 'ingest', 'adapter']

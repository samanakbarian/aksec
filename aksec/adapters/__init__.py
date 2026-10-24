"""Adapters that transform output from existing tools into the ingest contract.

These modules do **not** scan or probe anything. They read a file a tool has
already produced and translate it into `Observation` NDJSON (see
docs/DATA_SCHEMA.md), so existing, authorised results can flow into aksec.
"""

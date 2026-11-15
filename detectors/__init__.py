"""
detectors — PHP fingerprinting detector modules.

Each detector module runs one independent detection method and returns a
standardized dict of evidence. The PhpFingerprinter in core/fingerprint.py
aggregates all detector outputs into a PhpFingerprint.
"""

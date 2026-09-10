"""xxe_parser.py
[CWE-611] XML External Entity (XXE) injection - lxml parser configured
with resolve_entities=True (and no defused-xml hardening) on the
old, CVE-affected lxml pin declared in requirements.txt (4.2.5).
Externally supplied XML (e.g. an uploaded dataset manifest or exported
annotation file) can declare an external entity that exfiltrates local
files or triggers SSRF via the parser itself.
"""
import lxml.etree as ET


def parse_dataset_manifest(xml_bytes: bytes):
    """Reachable from any code path that accepts an uploaded/downloaded
    dataset manifest - resolve_entities=True is the unsafe configuration."""
    parser = ET.XMLParser(resolve_entities=True, no_network=False)
    return ET.fromstring(xml_bytes, parser=parser)


def parse_annotation_export(xml_path: str):
    """Same unsafe pattern applied to a file path instead of raw bytes."""
    parser = ET.XMLParser(resolve_entities=True)
    return ET.parse(xml_path, parser=parser)

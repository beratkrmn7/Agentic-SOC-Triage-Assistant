import json
import hashlib
from typing import Iterator, Union, Dict, Any, Iterable, Optional
from pathlib import Path
from datetime import datetime, timezone
import logging

from agent.ingestion.models import InputFormat, RecordEnvelope
from agent.ingestion.limits import IngestionLimits
from agent.errors import (
    InputTooLargeError, 
    RecordLimitExceededError,
    UnsupportedInputFormatError,
    InvalidEncodingError
)
from agent.ingestion.fingerprint import get_schema_fingerprint

logger = logging.getLogger(__name__)

def detect_input_format(path: Path, first_bytes: bytes) -> InputFormat:
    """Detect format from file extension and first few bytes via content sniffing."""
    if not first_bytes:
        return InputFormat.UNKNOWN

    # Check for binary
    text_chars = bytearray({7,8,9,10,12,13,27} | set(range(0x20, 0x100)) - {0x7f})
    is_binary = bool(first_bytes.translate(None, text_chars))
    if is_binary:
        return InputFormat.UNKNOWN

    try:
        content = first_bytes.decode('utf-8', errors='ignore').strip()
    except UnicodeDecodeError:
        return InputFormat.UNKNOWN

    if content.startswith('['):
        return InputFormat.JSON_ARRAY
    elif content.startswith('{'):
        # Could be JSON_OBJECT or JSONL
        # Usually JSONL has newlines, but difficult to tell definitively from first bytes
        if path.suffix.lower() in ['.jsonl', '.ndjson']:
            return InputFormat.JSONL
        elif path.suffix.lower() in ['.log', '.txt']:
            return InputFormat.TEXT_LOG
        elif '\n' in content:
            first_line = content.split('\n')[0].strip()
            if first_line.endswith('}'):
                try:
                    json.loads(first_line)
                    return InputFormat.JSONL
                except json.JSONDecodeError:
                    pass
        return InputFormat.JSON_OBJECT
    elif content.startswith('CEF:'):
        return InputFormat.CEF
    elif content.startswith('<') and '>' in content[:10]:
        return InputFormat.SYSLOG
    
    return InputFormat.UNKNOWN

def create_envelope(
    source_name: str,
    raw_record: Union[Dict[str, Any], str],
    line_number: Optional[int] = None,
    byte_offset: Optional[int] = None
) -> RecordEnvelope:
    
    if isinstance(raw_record, dict):
        raw_str = json.dumps(raw_record, sort_keys=True)
    else:
        raw_str = str(raw_record)
        
    record_hash = hashlib.sha256(raw_str.encode('utf-8', errors='ignore')).hexdigest()
    fingerprint = get_schema_fingerprint(raw_record)
    
    return RecordEnvelope(
        source_name=source_name,
        line_number=line_number,
        byte_offset=byte_offset,
        raw_record=raw_record,
        raw_record_hash=record_hash,
        schema_fingerprint=fingerprint,
        received_at=datetime.now(timezone.utc)
    )

def iter_jsonl_records(path: Path, limits: IngestionLimits) -> Iterator[RecordEnvelope]:
    source_name = path.name
    encoding_errors = 'replace' if limits.ALLOW_ENCODING_REPLACEMENT else 'strict'
    with open(path, 'rb') as f:
        byte_offset = 0
        records_yielded = 0
        
        for line_number, line_bytes in enumerate(f, 1):
            if records_yielded >= limits.MAX_RECORDS_PER_FILE:
                raise RecordLimitExceededError(f"Exceeded max records limit: {limits.MAX_RECORDS_PER_FILE}")
            
            line_len = len(line_bytes)
            if line_len > limits.MAX_RECORD_BYTES:
                logger.warning(f"Skipping line {line_number} in {source_name}: Exceeds MAX_RECORD_BYTES")
                byte_offset += line_len
                continue
                
            try:
                line_str = line_bytes.decode('utf-8', errors=encoding_errors).strip()
            except UnicodeDecodeError as e:
                raise InvalidEncodingError(f"Invalid UTF-8 encoding at line {line_number} in {source_name}: {e}")
                
            if not line_str:
                byte_offset += line_len
                continue
                
            try:
                raw_record = json.loads(line_str)
                yield create_envelope(source_name, raw_record, line_number, byte_offset)
                records_yielded += 1
            except json.JSONDecodeError as e:
                logger.warning(f"Malformed JSON line {line_number} in {source_name}: {e}. Yielding with framing_error.")
                env = create_envelope(source_name, line_str, line_number, byte_offset)
                env.framing_error = "malformed_json"
                yield env
                records_yielded += 1
            
            byte_offset += line_len

def iter_json_array_records(path: Path, limits: IngestionLimits) -> Iterator[RecordEnvelope]:
    import ijson
    source_name = path.name
    with open(path, 'rb') as f:
        try:
            records_yielded = 0
            for item in ijson.items(f, 'item'):
                if records_yielded >= limits.MAX_RECORDS_PER_FILE:
                    raise RecordLimitExceededError(f"Exceeded max records limit: {limits.MAX_RECORDS_PER_FILE}")
                
                if isinstance(item, dict):
                    yield create_envelope(source_name, item, line_number=records_yielded+1)
                else:
                    env = create_envelope(source_name, str(item), line_number=records_yielded+1)
                    env.framing_error = "malformed_json"
                    yield env
                records_yielded += 1
        except Exception as e:
            raise UnsupportedInputFormatError(f"Invalid JSON Array: {e}")

def iter_json_object_records(path: Path, limits: IngestionLimits) -> Iterator[RecordEnvelope]:
    """Reads a file containing a single JSON object."""
    if path.stat().st_size > limits.MAX_UPLOAD_BYTES:
        raise InputTooLargeError(f"JSON Object file exceeds upload limit ({limits.MAX_UPLOAD_BYTES} bytes).")
        
    source_name = path.name
    with open(path, 'r', encoding='utf-8') as f:
        try:
            data = json.load(f)
            if not isinstance(data, dict):
                raise UnsupportedInputFormatError("File does not contain a single JSON object.")
            yield create_envelope(source_name, data, line_number=1)
        except json.JSONDecodeError as e:
            raise UnsupportedInputFormatError(f"Invalid JSON Object: {e}")

def iter_text_records(path: Path, limits: IngestionLimits) -> Iterator[RecordEnvelope]:
    source_name = path.name
    encoding_errors = 'replace' if limits.ALLOW_ENCODING_REPLACEMENT else 'strict'
    with open(path, 'rb') as f:
        byte_offset = 0
        records_yielded = 0
        
        for line_number, line_bytes in enumerate(f, 1):
            if records_yielded >= limits.MAX_RECORDS_PER_FILE:
                raise RecordLimitExceededError(f"Exceeded max records limit: {limits.MAX_RECORDS_PER_FILE}")
            
            line_len = len(line_bytes)
            if line_len > limits.MAX_RECORD_BYTES:
                logger.warning(f"Skipping line {line_number} in {source_name}: Exceeds MAX_RECORD_BYTES")
                byte_offset += line_len
                continue
                
            try:
                line_str = line_bytes.decode('utf-8', errors=encoding_errors).strip()
            except UnicodeDecodeError as e:
                raise InvalidEncodingError(f"Invalid UTF-8 encoding at line {line_number} in {source_name}: {e}")
                
            if not line_str:
                byte_offset += line_len
                continue
                
            if line_str.startswith('{'):
                try:
                    raw_record = json.loads(line_str)
                    yield create_envelope(source_name, raw_record, line_number, byte_offset)
                    records_yielded += 1
                    byte_offset += line_len
                    continue
                except json.JSONDecodeError:
                    pass
                
            yield create_envelope(source_name, line_str, line_number, byte_offset)
            records_yielded += 1
            byte_offset += line_len

def iter_input_records(records: Iterable[Union[Dict[str, Any], str]], source_name: str, limits: IngestionLimits) -> Iterator[RecordEnvelope]:
    """Generator for processing an in-memory iterable of dicts or strings (like from an API)."""
    for idx, record in enumerate(records):
        if idx >= limits.MAX_RECORDS_PER_FILE:
            raise RecordLimitExceededError(f"Exceeded max records limit: {limits.MAX_RECORDS_PER_FILE}")
            
        if isinstance(record, str) and record.strip().startswith("{"):
            try:
                record = json.loads(record)
            except json.JSONDecodeError:
                pass
                
        yield create_envelope(source_name, record, line_number=idx+1)

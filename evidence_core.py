"""
evidence_core.py - the "engine" of EvidenceGuard.

This file contains ALL the forensic logic (hashing, comparing, validating,
reading image metadata, building reports). It deliberately does NOT import
Streamlit, so:
  * the automated tests can run quickly without a web server, and
  * the logic is easy to read and reuse.

app.py only draws the web page and calls the functions in this file.

Privacy design: every function works on bytes held in memory. Nothing in this
module writes uploaded evidence to disk, sends it over a network, or logs it.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import io
import json
import mimetypes
import os
import re
import secrets
import warnings
from datetime import datetime, timezone

from PIL import Image, UnidentifiedImageError
from PIL.ExifTags import GPSTAGS, TAGS

# --------------------------------------------------------------------------
# Settings
# --------------------------------------------------------------------------
APP_NAME = "EvidenceGuard"
APP_VERSION = "1.1.0"

MAX_FILE_SIZE_MB = 25
MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024
MAX_FILES_PER_BATCH = 10  # keeps memory use small on free hosting
HASH_CHUNK_SIZE = 1024 * 1024  # hash 1 MB at a time

# Safety limit so a "decompression bomb" image cannot exhaust memory.
Image.MAX_IMAGE_PIXELS = 50_000_000

# File extensions the app accepts (lower-case, without the dot).
ALLOWED_EXTENSIONS = (
    "jpg", "jpeg", "png", "gif", "bmp", "webp", "tif", "tiff",  # images
    "pdf", "txt", "csv", "log", "json", "xml", "md",            # documents / text
    "doc", "docx", "xls", "xlsx", "pptx", "zip", "mp4",         # office / archive / video
)

# Comparison results
STATUS_MATCH = "MATCH"
STATUS_MISMATCH = "MISMATCH"
STATUS_INVALID = "INVALID REFERENCE"
STATUS_NONE = "NO REFERENCE PROVIDED"

# --------------------------------------------------------------------------
# Wording used in the app and in reports (kept in one place on purpose)
# --------------------------------------------------------------------------
DISCLAIMER = (
    "A matching SHA-256 hash only shows that this file is byte-for-byte identical "
    "to whatever the reference hash was calculated from. It does NOT prove that the "
    "content is true, original, unedited before the reference was made, or "
    "authentic, and it says nothing about who created it or when. The result is only "
    "as trustworthy as the source of the reference hash."
)

LIMITATIONS = [
    "Hash comparison detects ANY change to the bytes (even re-saving or re-compressing), "
    "but it cannot say what changed, who changed it, or why.",
    "A hash cannot tell you whether the reference value itself is trustworthy. Obtain "
    "reference hashes from an independent, trusted source.",
    "Metadata (such as EXIF) is data stored INSIDE the file. It can be missing, "
    "stripped by apps and social media, edited, or deliberately forged. Its presence "
    "does not prove authenticity and its absence does not prove tampering.",
    "Camera date/time stamps usually have no time-zone information and depend on the "
    "device clock setting, which may have been wrong.",
    "This tool does not detect image manipulation, deepfakes or forgery. It never labels "
    "an image as manipulated.",
    "This is a learning/hackathon prototype and not a certified forensic tool. It is "
    "not a substitute for a qualified examiner, legal advice, or a documented chain of "
    "custody.",
]

METADATA_CAUTIONS = [
    "Metadata shown above is what the file CLAIMS about itself. It was not independently verified.",
    "A 'Software' value can come from camera firmware, a phone OS update, or an editing "
    "program. On its own it does not show that the image was edited.",
    "Missing metadata is common (messaging apps and social media strip it) and is not "
    "evidence of tampering.",
    "Date/time fields have no time zone and can be changed by anyone with basic tools.",
]

# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")


def now_utc_iso() -> str:
    """Current time in UTC, ISO-8601 format, to the second."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def generate_case_id() -> str:
    """Random case ID like EG-2026-A1B2C3 (not derived from any personal data)."""
    return f"EG-{datetime.now(timezone.utc).year}-{secrets.token_hex(3).upper()}"


def sanitize_case_id(raw: str | None) -> str:
    """Keep only letters, digits, '-' and '_' so IDs are safe in filenames/reports."""
    cleaned = re.sub(r"[^A-Za-z0-9_-]", "", raw or "")
    return cleaned[:40]


def safe_filename(name: str | None) -> str:
    """Strip folder parts and control characters from an uploaded filename."""
    text = (name or "").replace("\\", "/").split("/")[-1]
    text = _CONTROL_RE.sub("", text).strip()
    return text[:150] or "unnamed"


def get_extension(filename: str) -> str:
    """Lower-case extension without the dot ('' if none)."""
    return os.path.splitext(filename)[1].lstrip(".").lower()


def markdown_safe(text: str) -> str:
    """Make a filename safe to place inside Streamlit markdown text."""
    return re.sub(r"[*_`\[\]()<>#~|\\$]", "_", text)


def human_size(num_bytes: int) -> str:
    """12345 -> '12.1 KB'."""
    size = float(num_bytes)
    for unit in ("bytes", "KB", "MB", "GB"):
        if size < 1024 or unit == "GB":
            return f"{int(size)} bytes" if unit == "bytes" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{num_bytes} bytes"


# --------------------------------------------------------------------------
# SHA-256 hashing
# --------------------------------------------------------------------------
def sha256_hex(data: bytes) -> str:
    """SHA-256 of a bytes object, as 64 lower-case hex characters."""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("sha256_hex expects bytes")
    digest = hashlib.sha256()
    view = memoryview(data)
    for start in range(0, len(view), HASH_CHUNK_SIZE):
        digest.update(view[start:start + HASH_CHUNK_SIZE])
    return digest.hexdigest()


def sha256_stream(fileobj, chunk_size: int = HASH_CHUNK_SIZE) -> str:
    """SHA-256 of any file-like object opened in binary mode (read in chunks)."""
    digest = hashlib.sha256()
    while True:
        chunk = fileobj.read(chunk_size)
        if not chunk:
            break
        digest.update(chunk)
    return digest.hexdigest()


# --------------------------------------------------------------------------
# Reference-hash comparison
# --------------------------------------------------------------------------
_PREFIX_RE = re.compile(r"^\s*sha-?256\s*[:=]?\s*", re.IGNORECASE)
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")


def normalize_reference(raw: str | None) -> tuple[str, str | None]:
    """
    Clean up a hash typed or pasted by the user.

    Returns (normalized_hash, error_message).
      * ("", None)       -> nothing was provided
      * ("abc...", None) -> a valid 64-character hex SHA-256
      * ("", "reason")   -> the text is not a valid SHA-256
    """
    if raw is None:
        return "", None
    text = raw.strip()
    if not text:
        return "", None

    text = _PREFIX_RE.sub("", text)  # allow "sha256:<hash>"

    # Accept the output of the `sha256sum` command: "<hash>  filename"
    first_token = text.split()[0].lower() if text.split() else ""
    if _HEX64_RE.match(first_token):
        return first_token, None

    # Otherwise remove spaces and colons (e.g. "AB:CD:..." style) and lower-case.
    compact = re.sub(r"[\s:]", "", text).lower()

    if not re.fullmatch(r"[0-9a-f]*", compact):
        return "", "The reference contains characters that are not hexadecimal (0-9, a-f)."
    if len(compact) != 64:
        hint = ""
        if len(compact) == 32:
            hint = " That length matches MD5, but this tool only supports SHA-256."
        elif len(compact) == 40:
            hint = " That length matches SHA-1, but this tool only supports SHA-256."
        return "", f"A SHA-256 hash has exactly 64 hex characters; this has {len(compact)}.{hint}"
    return compact, None


def compare_hash(calculated_hex: str, reference_raw: str | None) -> dict:
    """
    Compare the calculated hash with the user's reference hash.

    Returns a dict: {"status", "detail", "reference_normalized"}.
    """
    normalized, error = normalize_reference(reference_raw)

    if error is not None:
        return {"status": STATUS_INVALID, "detail": error, "reference_normalized": ""}
    if not normalized:
        return {
            "status": STATUS_NONE,
            "detail": "No reference hash was entered, so no comparison was made.",
            "reference_normalized": "",
        }

    # compare_digest is a constant-time comparison (good habit for hash checks).
    if hmac.compare_digest(calculated_hex.strip().lower(), normalized):
        return {
            "status": STATUS_MATCH,
            "detail": (
                "The calculated SHA-256 equals the reference you supplied. This shows "
                "byte-level consistency with that reference only. It does not show the "
                "content is true or authentic, or that the reference itself is trustworthy."
            ),
            "reference_normalized": normalized,
        }
    return {
        "status": STATUS_MISMATCH,
        "detail": (
            "The calculated SHA-256 differs from the reference, so the bytes of this file "
            "are not identical to what the reference was computed from. Possible causes "
            "include modification, corruption, re-saving or re-encoding, a different file "
            "version, or a mistyped reference. This tool cannot tell which."
        ),
        "reference_normalized": normalized,
    }


# --------------------------------------------------------------------------
# Upload validation and type detection
# --------------------------------------------------------------------------
def validate_upload(filename: str, size_bytes: int) -> list[str]:
    """Return a list of problems (empty list = file is acceptable)."""
    problems = []
    ext = get_extension(filename)
    if not ext:
        problems.append("The file has no extension, so its type cannot be checked.")
    elif ext not in ALLOWED_EXTENSIONS:
        problems.append(f"File type '.{ext}' is not supported.")
    if size_bytes == 0:
        problems.append("The file is empty (0 bytes).")
    elif size_bytes > MAX_FILE_SIZE_BYTES:
        problems.append(
            f"The file is {human_size(size_bytes)}; the limit is {MAX_FILE_SIZE_MB} MB."
        )
    return problems


# (starting bytes, label, MIME type) - "magic numbers" at the start of a file
_SIGNATURES = [
    (b"\xff\xd8\xff", "JPEG", "image/jpeg"),
    (b"\x89PNG\r\n\x1a\n", "PNG", "image/png"),
    (b"GIF87a", "GIF", "image/gif"),
    (b"GIF89a", "GIF", "image/gif"),
    (b"%PDF-", "PDF", "application/pdf"),
    (b"II*\x00", "TIFF", "image/tiff"),
    (b"MM\x00*", "TIFF", "image/tiff"),
    (b"PK\x03\x04", "ZIP", "application/zip"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "OLE2", "application/x-ole-storage"),
]

# Which signature labels are normal for each extension.
_EXPECTED_SIGNATURE = {
    "jpg": {"JPEG"}, "jpeg": {"JPEG"}, "png": {"PNG"}, "gif": {"GIF"},
    "webp": {"WEBP"}, "pdf": {"PDF"}, "tif": {"TIFF"}, "tiff": {"TIFF"},
    "docx": {"ZIP"}, "xlsx": {"ZIP"}, "pptx": {"ZIP"}, "zip": {"ZIP"},
    "mp4": {"MP4"}, "doc": {"OLE2"}, "xls": {"OLE2"},
}
_TEXT_EXTENSIONS = {"txt", "csv", "log", "json", "xml", "md"}
_IMAGE_SIGNATURES = {"JPEG", "PNG", "GIF", "WEBP", "TIFF"}
_IMAGE_EXTENSIONS = {"jpg", "jpeg", "png", "gif", "bmp", "webp", "tif", "tiff"}


def detect_signature(data: bytes) -> tuple[str | None, str | None]:
    """Look at the first bytes of the file. Returns (label, mime) or (None, None)."""
    head = bytes(data[:16])
    if head[:4] == b"RIFF" and bytes(data[8:12]) == b"WEBP":
        return "WEBP", "image/webp"
    if bytes(data[4:8]) == b"ftyp":
        return "MP4", "video/mp4"
    for prefix, label, mime in _SIGNATURES:
        if head.startswith(prefix):
            return label, mime
    return None, None


def check_extension_consistency(ext: str, signature_label: str | None) -> str | None:
    """
    Compare the filename extension with the content signature.
    Returns a plain-language OBSERVATION, or None if nothing unusual was seen.
    """
    if ext in _EXPECTED_SIGNATURE:
        expected = _EXPECTED_SIGNATURE[ext]
        if signature_label is None:
            return (
                f"The extension is .{ext}, but the file does not start with a recognised "
                f"{'/'.join(sorted(expected))} signature."
            )
        if signature_label not in expected:
            return (
                f"The extension is .{ext}, but the file content starts like a "
                f"{signature_label} file."
            )
    elif ext in _TEXT_EXTENSIONS and signature_label is not None:
        return (
            f"The extension is .{ext} (text), but the file content starts like a "
            f"{signature_label} file."
        )
    return None


def looks_like_image(ext: str, signature_label: str | None) -> bool:
    """Decide whether to try reading image metadata."""
    if signature_label is not None:
        return signature_label in _IMAGE_SIGNATURES
    return ext in _IMAGE_EXTENSIONS


# --------------------------------------------------------------------------
# Image metadata (EXIF) extraction with Pillow
# --------------------------------------------------------------------------
# EXIF fields most useful to an investigator, shown first.
KEY_EXIF_FIELDS = (
    "Make", "Model", "LensModel", "Software", "DateTime", "DateTimeOriginal",
    "DateTimeDigitized", "Orientation", "ExposureTime", "FNumber",
    "ISOSpeedRatings", "FocalLength", "Flash", "ExifImageWidth", "ExifImageHeight",
)
_POINTER_TAGS = {0x8769, 0x8825, 0xA005}  # pointers to other EXIF blocks
_MAKERNOTE_TAG = 0x927C  # large binary blob, not useful here


def _format_value(value, depth: int = 0) -> str:
    """Turn any EXIF value into short, safe, printable text."""
    if isinstance(value, (bytes, bytearray)):
        return f"<{len(value)} bytes of binary data>"
    if isinstance(value, (int, str)):
        return _CONTROL_RE.sub("", str(value))[:200]
    if hasattr(value, "numerator") and hasattr(value, "denominator"):  # a fraction
        try:
            return str(round(float(value), 6))
        except Exception:  # e.g. division by zero
            return _CONTROL_RE.sub("", str(value))[:200]
    if isinstance(value, (tuple, list)) and depth < 2:
        return "(" + ", ".join(_format_value(v, depth + 1) for v in list(value)[:16]) + ")"
    return _CONTROL_RE.sub("", str(value))[:200]


def extract_image_metadata(data: bytes) -> dict:
    """
    Read basic image properties and EXIF tags. NEVER raises: problems are reported
    in the returned dict so a bad file cannot crash the app.

    Everything returned here is OBSERVED data copied from the file.
    """
    result = {
        "attempted": True,
        "readable": False,
        "format": None,
        "width": None,
        "height": None,
        "mode": None,
        "exif_present": False,
        "key_fields": {},
        "all_fields": {},
        "gps_present": False,
        "gps": {},
        "error": None,
    }
    try:
        with warnings.catch_warnings():
            # Treat "suspiciously large image" warnings as errors.
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(io.BytesIO(data)) as img:
                result.update(
                    readable=True, format=img.format,
                    width=img.width, height=img.height, mode=img.mode,
                )
                exif = img.getexif()

                fields: dict[str, str] = {}

                def collect(items):
                    for tag_id, value in items:
                        if tag_id in _POINTER_TAGS or tag_id == _MAKERNOTE_TAG:
                            continue
                        name = TAGS.get(tag_id, f"Tag_{tag_id}")
                        fields[name] = _format_value(value)

                collect(exif.items())
                try:
                    collect(exif.get_ifd(0x8769).items())  # Exif sub-block (DateTimeOriginal ...)
                except Exception:
                    pass

                gps: dict[str, str] = {}
                try:
                    for tag_id, value in exif.get_ifd(0x8825).items():
                        gps[GPSTAGS.get(tag_id, f"GPSTag_{tag_id}")] = _format_value(value)
                except Exception:
                    pass

                result["all_fields"] = fields
                result["exif_present"] = bool(fields or gps)
                result["key_fields"] = {k: fields[k] for k in KEY_EXIF_FIELDS if k in fields}
                result["gps"] = gps
                result["gps_present"] = bool(gps)
    except (Image.DecompressionBombError, Image.DecompressionBombWarning):
        result.update(readable=False, error="Image is unusually large and was not opened.")
    except (UnidentifiedImageError, OSError, ValueError, SyntaxError) as exc:
        # Only the exception TYPE is kept - messages could echo file content.
        result.update(readable=False, error=f"Not readable as an image ({type(exc).__name__}).")
    except Exception as exc:  # last-resort safety net
        result.update(readable=False, error=f"Unexpected error ({type(exc).__name__}).")
    return result


# --------------------------------------------------------------------------
# Building the evidence record
# --------------------------------------------------------------------------
def build_record(
    case_id: str,
    filename: str,
    data: bytes,
    declared_mime: str | None = None,
    reference_raw: str | None = None,
    sha256_value: str | None = None,
) -> dict:
    """
    Analyse one file and return a plain dict (the "evidence record").
    The record never contains the file bytes themselves.
    """
    name = safe_filename(filename)
    ext = get_extension(name)
    sha = sha256_value or sha256_hex(data)
    sig_label, sig_mime = detect_signature(data)
    comparison = compare_hash(sha, reference_raw)

    if looks_like_image(ext, sig_label):
        metadata = extract_image_metadata(data)
    else:
        metadata = {"attempted": False}

    ref_text = comparison["reference_normalized"] or _CONTROL_RE.sub("", reference_raw or "")[:200].strip()

    return {
        "case_id": sanitize_case_id(case_id) or "UNSET",
        "filename": name,
        "size_bytes": len(data),
        "mime_declared_by_browser": declared_mime or "not provided",
        "mime_guessed_from_extension": mimetypes.guess_type(name)[0] or "unknown",
        "type_from_content_signature": sig_label or "no known signature",
        "mime_from_content_signature": sig_mime or "unknown",
        "extension_observation": check_extension_consistency(ext, sig_label),
        "sha256": sha,
        "hash_algorithm": "SHA-256",
        "reference_supplied": ref_text,
        "comparison_status": comparison["status"],
        "comparison_detail": comparison["detail"],
        "analyzed_at_utc": now_utc_iso(),
        "image_metadata": metadata,
        "tool": f"{APP_NAME} {APP_VERSION}",
    }


def redact_record(record: dict, include_gps: bool) -> dict:
    """Copy a record; remove GPS coordinates unless the user opted in."""
    rec = copy.deepcopy(record)
    meta = rec.get("image_metadata") or {}
    if meta.get("gps_present") and not include_gps:
        meta["gps"] = {"note": "GPS data was present in the file but was left out of this report."}
    return rec


# --------------------------------------------------------------------------
# Reports
# --------------------------------------------------------------------------
def render_json_report(case_id: str, records: list[dict], include_gps: bool = False) -> str:
    """Investigation report as pretty JSON text."""
    report = {
        "report_type": f"{APP_NAME} integrity report",
        "tool": f"{APP_NAME} {APP_VERSION}",
        "case_id": sanitize_case_id(case_id) or "UNSET",
        "generated_at_utc": now_utc_iso(),
        "disclaimer": DISCLAIMER,
        "limitations": LIMITATIONS,
        "metadata_cautions": METADATA_CAUTIONS,
        "evidence_count": len(records),
        "evidence": [redact_record(r, include_gps) for r in records],
    }
    return json.dumps(report, indent=2, ensure_ascii=False)


def _wrap(text: str, width: int = 78, indent: str = "  ") -> list[str]:
    """Very small word-wrapper for the TXT report."""
    words, lines, line = text.split(), [], indent
    for word in words:
        if len(line) + len(word) + 1 > width and line.strip():
            lines.append(line.rstrip())
            line = indent
        line += word + " "
    if line.strip():
        lines.append(line.rstrip())
    return lines


def render_txt_report(case_id: str, records: list[dict], include_gps: bool = False) -> str:
    """Investigation report as human-readable text."""
    bar = "=" * 78
    out = [
        bar,
        f"{APP_NAME.upper()} - DIGITAL EVIDENCE INTEGRITY REPORT",
        bar,
        f"Case ID            : {sanitize_case_id(case_id) or 'UNSET'}",
        f"Report generated   : {now_utc_iso()} (UTC)",
        f"Tool               : {APP_NAME} {APP_VERSION}",
        f"Files in report    : {len(records)}",
        "",
        "IMPORTANT DISCLAIMER",
        *_wrap(DISCLAIMER),
        "",
    ]

    for number, original in enumerate(records, start=1):
        rec = redact_record(original, include_gps)
        meta = rec.get("image_metadata") or {}
        title = f"EVIDENCE ITEM {rec['evidence_id']}" if rec.get("evidence_id") else f"EVIDENCE ITEM {number}"
        out += ["-" * 78, title, "-" * 78]
        out += [
            f"File name          : {rec['filename']}",
            f"File size          : {rec['size_bytes']} bytes ({human_size(rec['size_bytes'])})",
            f"Analysed at        : {rec['analyzed_at_utc']} (UTC)",
            "",
            "[OBSERVED] Type information",
            f"  MIME declared by browser      : {rec['mime_declared_by_browser']}",
            f"  MIME guessed from extension   : {rec['mime_guessed_from_extension']}",
            f"  Type from content signature   : {rec['type_from_content_signature']}",
        ]
        if rec.get("extension_observation"):
            out += ["  Observation: " + rec["extension_observation"]]
        out += [
            "",
            "[OBSERVED] Hash comparison",
            f"  Algorithm                     : {rec['hash_algorithm']}",
            f"  Calculated SHA-256            : {rec['sha256']}",
            f"  Reference supplied by user    : {rec['reference_supplied'] or '(none)'}",
            f"  RESULT                        : {rec['comparison_status']}",
            *_wrap(rec["comparison_detail"], indent="  "),
            "",
            "[OBSERVED] Image metadata",
        ]
        if not meta.get("attempted"):
            out.append("  Not applicable (file was not identified as an image).")
        elif not meta.get("readable"):
            out.append(f"  Could not be read: {meta.get('error')}")
        else:
            out += [
                f"  Format / size / mode : {meta['format']} / {meta['width']}x{meta['height']} / {meta['mode']}",
            ]
            if meta["exif_present"]:
                out.append("  Key EXIF fields:")
                for key, value in meta["key_fields"].items():
                    out.append(f"    {key}: {value}")
                if not meta["key_fields"]:
                    out.append("    (none of the commonly used fields were present)")
                if meta["gps_present"]:
                    out.append("  GPS tags:")
                    for key, value in meta["gps"].items():
                        out.append(f"    {key}: {value}")
            else:
                out.append("  No EXIF metadata found in this file.")
            out += ["", "[CAUTIONS - not findings] How to read the metadata"]
            for caution in METADATA_CAUTIONS:
                out += _wrap("- " + caution)
        out.append("")

    out += ["-" * 78, "LIMITATIONS OF THIS ANALYSIS", "-" * 78]
    for item in LIMITATIONS:
        out += _wrap("- " + item)
    out += [
        "",
        "This tool did not upload any file to an external service, and it did not",
        "store the evidence files. Only the values listed above are in this report.",
        bar,
    ]
    return "\n".join(out) + "\n"

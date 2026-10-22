"""
Automated tests for EvidenceGuard's core logic.

Run from the project folder with:   pytest -v
All test data is created in memory and is fictional.
"""

import hashlib
import io
import json

import pytest
from PIL import Image

import evidence_core as core

# Official test vectors for SHA-256 (published in NIST/FIPS examples).
EMPTY_SHA = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
ABC_SHA = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"


# ---------------------------------------------------------------- hashing
def test_sha256_known_vectors():
    assert core.sha256_hex(b"") == EMPTY_SHA
    assert core.sha256_hex(b"abc") == ABC_SHA


def test_sha256_matches_hashlib_for_large_data():
    data = b"\x00\x01\x02" * 1_000_000  # ~3 MB, crosses the 1 MB chunk size
    assert core.sha256_hex(data) == hashlib.sha256(data).hexdigest()


def test_sha256_stream_equals_bytes_version():
    data = b"fictional evidence " * 5000
    assert core.sha256_stream(io.BytesIO(data), chunk_size=100) == core.sha256_hex(data)


def test_one_changed_byte_changes_hash():
    original = b"Door unlocked at 09:15"
    changed = b"Door unlocked at 09:51"
    assert core.sha256_hex(original) != core.sha256_hex(changed)


def test_sha256_rejects_text_input():
    with pytest.raises(TypeError):
        core.sha256_hex("not bytes")


# ------------------------------------------------------ reference comparison
def test_match():
    result = core.compare_hash(ABC_SHA, ABC_SHA)
    assert result["status"] == core.STATUS_MATCH


@pytest.mark.parametrize(
    "reference",
    [
        ABC_SHA.upper(),                       # upper-case
        "  " + ABC_SHA + "\n",                 # extra whitespace
        "sha256:" + ABC_SHA,                   # prefix
        "SHA-256 " + ABC_SHA,                  # another prefix style
        ABC_SHA + "  evidence.txt",            # `sha256sum` command output
        ":".join(ABC_SHA[i:i + 2] for i in range(0, 64, 2)),  # AA:BB:CC style
    ],
)
def test_match_with_common_formats(reference):
    assert core.compare_hash(ABC_SHA, reference)["status"] == core.STATUS_MATCH


def test_mismatch_when_reference_is_valid_but_different():
    result = core.compare_hash(ABC_SHA, EMPTY_SHA)
    assert result["status"] == core.STATUS_MISMATCH


def test_mismatch_when_one_character_differs():
    almost = ABC_SHA[:-1] + ("0" if ABC_SHA[-1] != "0" else "1")
    assert core.compare_hash(ABC_SHA, almost)["status"] == core.STATUS_MISMATCH


@pytest.mark.parametrize(
    "reference",
    [
        "abc123",                    # too short
        ABC_SHA[:-1],                # 63 characters
        ABC_SHA + "0",               # 65 characters
        "z" * 64,                    # right length, not hex
        "hello world, not a hash",   # nonsense
        hashlib.md5(b"abc").hexdigest(),    # MD5 length
        hashlib.sha1(b"abc").hexdigest(),   # SHA-1 length
    ],
)
def test_invalid_reference(reference):
    result = core.compare_hash(ABC_SHA, reference)
    assert result["status"] == core.STATUS_INVALID
    assert result["detail"]  # an explanation is always given


@pytest.mark.parametrize("reference", [None, "", "   ", "\n\t"])
def test_no_reference_is_not_a_match_or_mismatch(reference):
    assert core.compare_hash(ABC_SHA, reference)["status"] == core.STATUS_NONE


def test_match_text_does_not_claim_authenticity():
    detail = core.compare_hash(ABC_SHA, ABC_SHA)["detail"].lower()
    assert "does not show" in detail and "authentic" in detail


def test_md5_hint_is_given():
    _, error = core.normalize_reference(hashlib.md5(b"x").hexdigest())
    assert "MD5" in error


# ------------------------------------------------------------- validation
def test_validate_accepts_normal_file():
    assert core.validate_upload("photo.JPG", 1000) == []


def test_validate_rejects_empty_file():
    assert core.validate_upload("note.txt", 0)


def test_validate_rejects_too_big():
    assert core.validate_upload("big.pdf", core.MAX_FILE_SIZE_BYTES + 1)


def test_validate_accepts_exactly_max_size():
    assert core.validate_upload("big.pdf", core.MAX_FILE_SIZE_BYTES) == []


@pytest.mark.parametrize("name", ["virus.exe", "script.py", "noextension"])
def test_validate_rejects_unsupported_types(name):
    assert core.validate_upload(name, 100)


def test_safe_filename_removes_folders_and_control_chars():
    assert core.safe_filename("../../etc/passwd") == "passwd"
    assert core.safe_filename("C:\\Users\\me\\evidence.txt") == "evidence.txt"
    assert core.safe_filename("bad\x00name\n.txt") == "badname.txt"
    assert core.safe_filename("") == "unnamed"
    assert core.safe_filename(None) == "unnamed"


def test_case_id_helpers():
    case_id = core.generate_case_id()
    assert case_id.startswith("EG-") and len(case_id.split("-")) == 3
    assert core.sanitize_case_id("My Case/../ID#1") == "MyCaseID1"
    assert core.generate_case_id() != core.generate_case_id()


def test_signature_and_extension_check():
    assert core.detect_signature(b"%PDF-1.7 ...")[0] == "PDF"
    assert core.detect_signature(b"\x89PNG\r\n\x1a\nxxxx")[0] == "PNG"
    assert core.detect_signature(b"just text")[0] is None
    # a text file renamed to .jpg is noticed, and is reported as an observation
    assert core.check_extension_consistency("jpg", None)
    assert core.check_extension_consistency("jpg", "PDF")
    assert core.check_extension_consistency("txt", "PNG")
    assert core.check_extension_consistency("txt", None) is None
    assert core.check_extension_consistency("pdf", "PDF") is None


# --------------------------------------------------------------- metadata
def _jpeg_with_exif() -> bytes:
    img = Image.new("RGB", (40, 30), (10, 20, 30))
    exif = Image.Exif()
    exif[0x010F] = "FictionCam"
    exif[0x0110] = "Demo-1"
    exif.get_ifd(0x8769)[0x9003] = "2026:01:15 10:30:00"
    buffer = io.BytesIO()
    img.save(buffer, "JPEG", exif=exif)
    return buffer.getvalue()


def test_exif_extraction_reads_camera_and_timestamp():
    meta = core.extract_image_metadata(_jpeg_with_exif())
    assert meta["readable"] and meta["exif_present"]
    assert meta["key_fields"]["Make"] == "FictionCam"
    assert meta["key_fields"]["Model"] == "Demo-1"
    assert meta["key_fields"]["DateTimeOriginal"] == "2026:01:15 10:30:00"
    assert meta["gps_present"] is False


def test_image_without_exif_is_handled():
    buffer = io.BytesIO()
    Image.new("RGB", (10, 10)).save(buffer, "PNG")
    meta = core.extract_image_metadata(buffer.getvalue())
    assert meta["readable"] is True
    assert meta["exif_present"] is False


@pytest.mark.parametrize(
    "bad_bytes",
    [
        b"this is not an image",
        b"\xff\xd8\xff\xe0 truncated jpeg",
        _jpeg_with_exif()[:60],               # JPEG cut off in the middle
        b"\x89PNG\r\n\x1a\n garbage",
    ],
)
def test_invalid_images_never_crash(bad_bytes):
    meta = core.extract_image_metadata(bad_bytes)  # must not raise
    assert meta["readable"] is False
    assert meta["error"]


def test_record_for_non_image_skips_metadata():
    rec = core.build_record("EG-TEST", "note.txt", b"hello", "text/plain", None)
    assert rec["image_metadata"] == {"attempted": False}
    assert rec["sha256"] == core.sha256_hex(b"hello")


def test_record_never_contains_file_bytes():
    secret = b"TOP-SECRET-FICTIONAL-CONTENT"
    rec = core.build_record("EG-TEST", "secret.txt", secret, "text/plain", None)
    assert "TOP-SECRET-FICTIONAL-CONTENT" not in json.dumps(rec)


def test_record_flags_renamed_file():
    rec = core.build_record("EG-TEST", "photo.jpg", b"plain text only", None, None)
    assert rec["extension_observation"]


# ---------------------------------------------------------------- reports
def _sample_record(reference=None, gps=False):
    rec = core.build_record("EG-TEST", "photo.jpg", _jpeg_with_exif(), "image/jpeg", reference)
    if gps:
        rec["image_metadata"]["gps_present"] = True
        rec["image_metadata"]["gps"] = {"GPSLatitude": "(12.0, 30.0, 0.0)"}
    return rec


def test_json_report_is_valid_and_has_disclaimer():
    rec = _sample_record(reference=core.sha256_hex(b"something else"))
    data = json.loads(core.render_json_report("EG-TEST", [rec]))
    assert data["case_id"] == "EG-TEST"
    assert data["evidence"][0]["comparison_status"] == core.STATUS_MISMATCH
    assert "does NOT prove" in data["disclaimer"]
    assert data["limitations"]


def test_txt_report_has_disclaimer_hash_and_result():
    rec = _sample_record()
    text = core.render_txt_report("EG-TEST", [rec])
    assert "DISCLAIMER" in text
    assert rec["sha256"] in text
    assert "NO REFERENCE PROVIDED" in text
    assert "[OBSERVED]" in text and "[CAUTIONS" in text


def test_reports_hide_gps_unless_opted_in():
    rec = _sample_record(gps=True)
    hidden_txt = core.render_txt_report("EG-TEST", [rec], include_gps=False)
    hidden_json = core.render_json_report("EG-TEST", [rec], include_gps=False)
    assert "GPSLatitude" not in hidden_txt and "GPSLatitude" not in hidden_json
    shown_json = core.render_json_report("EG-TEST", [rec], include_gps=True)
    assert "GPSLatitude" in shown_json
    assert "GPSLatitude" in rec["image_metadata"]["gps"]  # original record untouched


def test_report_never_says_authentic_or_manipulated_as_a_finding():
    rec = _sample_record(reference=core.sha256_hex(_jpeg_with_exif()))
    text = core.render_txt_report("EG-TEST", [rec]).lower()
    assert "is authentic" not in text
    assert "was manipulated" not in text and "is manipulated" not in text

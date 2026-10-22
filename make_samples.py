"""
make_samples.py - creates FICTIONAL test files in the samples/ folder.

Run:  python make_samples.py

Nothing here is real evidence. It also writes samples/SAMPLE_HASHES.txt, which
lists the SHA-256 of each file so you can paste a correct (or deliberately wrong)
reference hash into the app.
"""
import os

from PIL import Image

import evidence_core as core

OUT = "samples"
os.makedirs(OUT, exist_ok=True)

# 1) A fictional text note and a copy with ONE character changed.
note = (
    "FICTIONAL INCIDENT NOTE - FOR TESTING ONLY\n"
    "Case: Demo-001\n"
    "Observation: The server room door was found unlocked at 09:15.\n"
    "Witness: Alex Example (fictional person)\n"
).encode("utf-8")
tampered = note.replace(b"09:15", b"09:51")
with open(f"{OUT}/fictional_incident_note.txt", "wb") as f:
    f.write(note)
with open(f"{OUT}/fictional_incident_note_TAMPERED.txt", "wb") as f:
    f.write(tampered)

# 2) A fictional JPEG with made-up camera EXIF data.
img = Image.new("RGB", (320, 200), (30, 90, 160))
exif = Image.Exif()
exif[0x010F] = "FictionCam"                    # Make
exif[0x0110] = "Demo-1"                        # Model
exif[0x0131] = "FictionCam firmware 1.0"       # Software
exif[0x0132] = "2026:01:15 10:30:00"           # DateTime
exif.get_ifd(0x8769)[0x9003] = "2026:01:15 10:30:00"   # DateTimeOriginal
img.save(f"{OUT}/fictional_photo_with_exif.jpg", "JPEG", exif=exif)

# 3) A fictional PNG with no metadata at all.
Image.new("RGB", (200, 120), (160, 60, 60)).save(f"{OUT}/fictional_photo_no_exif.png")

# 4) A file with a misleading extension (a text file named .jpg).
with open(f"{OUT}/fictional_renamed_text.jpg", "wb") as f:
    f.write(b"This is plain text pretending to be a JPEG. Fictional test file.\n")

# Write the hash list.
lines = ["SHA-256 of the fictional sample files (for testing only)", ""]
for name in sorted(os.listdir(OUT)):
    if name == "SAMPLE_HASHES.txt":
        continue
    with open(f"{OUT}/{name}", "rb") as f:
        lines.append(f"{core.sha256_stream(f)}  {name}")
with open(f"{OUT}/SAMPLE_HASHES.txt", "w", encoding="utf-8") as f:
    f.write("\n".join(lines) + "\n")

print("\n".join(lines))

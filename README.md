# 🛡️ EvidenceGuard — Digital Evidence Integrity Checker

Cyber Hackathon 2026 project. Upload a file, get its **SHA-256 hash**, compare it with a
**reference hash**, read **image metadata (EXIF)**, and download a **TXT / JSON report**.
Built with Python, Streamlit, `hashlib`, Pillow and pytest.

> ⚠️ **Disclaimer.** A matching hash only shows that a file is **byte-for-byte identical to
> whatever the reference hash was calculated from**. It does **not** prove the content is true,
> original or authentic, and it says nothing about who made it or when. EvidenceGuard never
> labels an image as manipulated and never calls a file "authentic".

## Features
- Responsive interface (phone and desktop)
- Upload JPG, PNG, GIF, BMP, WEBP, TIFF, PDF, TXT, CSV, LOG, JSON, XML, MD, DOC/DOCX, XLS/XLSX, PPTX, ZIP, MP4
- SHA-256 for every file; result is **MATCH**, **MISMATCH**, **INVALID REFERENCE** (or "no reference yet")
- Accepts hashes in common formats (upper-case, `sha256:` prefix, `sha256sum` output, `AA:BB:..`)
- EXIF reading: camera make/model, software, timestamps, lens, exposure (GPS hidden by default)
- File name, size, MIME type (3 sources, clearly labelled), analysis time (UTC)
- Notices when a file's extension does not match its content (reported as an observation only)
- Case ID, per-session evidence log, downloadable reports (per file and per case)
- Validation of type and size (max 25 MB), safe handling of corrupt files

## Privacy and safety design
- Files are processed **in memory only**: not saved to disk, not uploaded to any external service.
- No file contents or filenames are written to logs; errors show only the error *type*.
- The evidence log lives only in the browser session (refresh = cleared).
- GPS coordinates are hidden on screen and left out of reports unless you opt in.
- Observed facts and cautions are shown in separate sections.
- `.gitignore` blocks reports, evidence folders and secrets from being committed.

## Project structure
```
evidenceguard/
├── app.py               # Streamlit web interface (draws the page)
├── evidence_core.py     # All logic: hashing, comparison, validation, EXIF, reports
├── make_samples.py      # Creates FICTIONAL test files in samples/
├── samples/             # Fictional files + SAMPLE_HASHES.txt
├── tests/
│   └── test_hashing.py  # Automated pytest tests
├── .streamlit/config.toml  # Upload limit + telemetry off
├── pytest.ini           # Lets tests import evidence_core
├── requirements.txt
├── .gitignore
└── README.md
```
(`evidence_core.py` is separate from `app.py` so the logic can be tested without a web server.)

---

## Run it on an Android phone (GitHub Codespaces — recommended)
Codespaces is a free coding environment that runs in your phone's browser.

1. In Chrome, open **github.com**, sign in (or create a free account).
2. Menu (⋮) → tick **Desktop site** (the code editor needs desktop layout).
3. Tap **+ → New repository**. Name it `evidenceguard`, set **Public**, tick **Add a README**, create.
4. Upload the project: **Add file → Upload files**, choose `evidenceguard.zip`, then **Commit changes**.
5. Tap **Code → Codespaces → Create codespace on main**. Wait for the editor to load.
6. Open the terminal (menu ☰ → Terminal → New Terminal) and type:
   ```bash
   unzip -o evidenceguard.zip
   cp -r evidenceguard/. .
   rm -rf evidenceguard evidenceguard.zip
   pip install -r requirements.txt
   python make_samples.py
   streamlit run app.py
   ```
7. A pop-up says "Your application is running on port 8501". Tap **Open in Browser**.
   (If it does not appear: open the **Ports** tab and tap the 🌐 icon next to port 8501.)

Tip: if typing on the phone is hard, create each file with **Explorer → New File** and paste
the code, using the same folder layout as above.

### Run the tests
```bash
pytest -v
```
All tests should show `PASSED`. If `pytest: command not found`, use `python -m pytest -v`.

---

## Testing with fictional evidence
Run `python make_samples.py` once. It creates `samples/` and `samples/SAMPLE_HASHES.txt`.

| Try this | Expected result |
|---|---|
| Upload `fictional_incident_note.txt`, paste its hash from `SAMPLE_HASHES.txt` | **MATCH** (still not proof of authenticity) |
| Upload `fictional_incident_note_TAMPERED.txt`, paste the **original note's** hash | **MISMATCH** (one character differs) |
| Paste `abc123` as a reference | **INVALID REFERENCE** (not 64 hex characters) |
| Upload `fictional_photo_with_exif.jpg` | Metadata tab shows FictionCam / Demo-1 / timestamps |
| Upload `fictional_photo_no_exif.png` | "No EXIF found — common, not evidence of tampering" |
| Upload `fictional_renamed_text.jpg` | Observation: extension is .jpg but content is not a JPEG |
| Upload an empty file or `.exe` | Clear error, app keeps working |

---

## Deploy on Streamlit Community Cloud (free)
1. Make sure the project files are in your GitHub repo (`app.py` and `requirements.txt` at the top level).
   In Codespaces: **Source Control** tab → type a message → **Commit** → **Sync/Push**.
2. Go to **share.streamlit.io** and sign in with GitHub.
3. Tap **Create app** → **Deploy a public app from GitHub**.
4. Pick repository `evidenceguard`, branch `main`, main file path `app.py`.
5. Tap **Deploy**. After a few minutes you get a public link like `https://<name>.streamlit.app`.
6. Open the link on your phone and repeat the sample tests. Put the link in your hackathon submission.

Notes: do not put real evidence in a public deployment. The app holds uploads only in
memory, but a public link is still open to anyone. The app needs no secrets or API keys.

---

## Hackathon demo plan (about 5 minutes)
1. **Problem (30 s):** "Digital evidence can be changed by one byte. How do we quickly check a file is unchanged from a reference?"
2. **Show MATCH (45 s):** upload the fictional note, paste the right hash → MATCH. Read the warning aloud: *consistent with the reference, not proof of authenticity.*
3. **Show MISMATCH (45 s):** upload the TAMPERED note with the original hash → MISMATCH. Explain it changed one character (09:15 → 09:51).
4. **Show INVALID REFERENCE (20 s):** paste a short or MD5-length hash; the app explains why.
5. **Metadata (60 s):** upload the EXIF photo; show *Observed* vs *Cautions*; then the no-EXIF PNG to show missing metadata ≠ tampering.
6. **Report + log (45 s):** add items to the evidence log, download the TXT and JSON case reports.
7. **Safety and honesty (45 s):** no uploads to third parties, nothing stored, GPS hidden by default, never says "authentic" or "manipulated", limitations listed.
8. **Tests (20 s):** show `pytest -v` passing; mention tests cover hashing and comparison.

Likely judge questions: *Can someone fake a matching hash?* → Only if they also control the reference;
that is why the reference must come from an independent trusted source. *Why not detect fake images?* →
Reliable manipulation detection needs specialist analysis; this tool avoids false accusations.

## Troubleshooting
- `ModuleNotFoundError` → run `pip install -r requirements.txt`.
- `streamlit: command not found` → run `python -m streamlit run app.py`.
- Page blank on Codespaces → open the Ports tab, make port 8501 visible, reload.
- Upload rejected → check type is in the allowed list and size is ≤ 25 MB.

## Limitations
This is a learning/hackathon prototype, not a certified forensic tool. See the
"Limitations & privacy" panel in the app for the full list.

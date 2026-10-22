"""
EvidenceGuard - Digital Evidence Integrity Checker (Cyber Hackathon 2026)

app.py draws the web page with Streamlit. All forensic logic lives in
evidence_core.py. Run with:   streamlit run app.py

Privacy: files are read into memory only, are never written to disk, never sent
to any external service, and are never printed to logs. The evidence log keeps
only metadata/hash values (not file contents) and disappears when the browser
session ends.
"""

import copy

import streamlit as st

import evidence_core as core

# --------------------------------------------------------------------------
# Page setup
# --------------------------------------------------------------------------
st.set_page_config(
    page_title="EvidenceGuard | Digital Forensics",
    page_icon="🛡️",
    layout="wide",  # responsive dashboard layout
    initial_sidebar_state="collapsed",
)

# Static CSS only (no user-provided text is ever injected into HTML).
st.markdown(
    """
    <style>
      .block-container { padding-top: 1rem; padding-bottom: 3rem; max-width: 1120px; }
      .eg-hero {
        background: linear-gradient(135deg, #081b33 0%, #123d72 55%, #1f6feb 100%);
        color: #ffffff; padding: 1.35rem 1.45rem; border: 1px solid #3568a6;
        border-radius: 18px; margin-bottom: 1rem; box-shadow: 0 8px 28px rgba(31,111,235,.14);
      }
      .eg-hero h1 { color: #ffffff; margin: 0; font-size: 2rem; line-height: 1.2; letter-spacing: -.02em; }
      .eg-hero p  { color: #e6efff; margin: .45rem 0 0 0; font-size: 1rem; }
      .eg-kicker { color: #93c5fd; font-weight: 700; text-transform: uppercase; letter-spacing: .12em; font-size: .72rem; }
      div[data-testid="stMetric"] { background: rgba(127, 127, 127, .08); padding: .8rem; border-radius: 12px; border: 1px solid rgba(127,127,127,.18); }
      div[data-testid="stTabs"] button { font-weight: 650; }
      code { word-break: break-all; }
      @media (max-width: 640px) {
        .eg-hero h1 { font-size: 1.5rem; }
        .eg-hero { padding: 1rem; border-radius: 14px; }
        .block-container { padding-left: 0.75rem; padding-right: 0.75rem; }
      }
    </style>
    <div class="eg-hero">
      <div class="eg-kicker">Digital forensics toolkit · Hackathon prototype</div>
      <h1>🛡️ EvidenceGuard</h1>
      <p>Check file fingerprints, inspect available metadata, and document your findings.</p>
    </div>
    """,
    unsafe_allow_html=True,
)


# --------------------------------------------------------------------------
# Session state (lives only as long as the browser tab/session)
# --------------------------------------------------------------------------
def init_state():
    ss = st.session_state
    if "case_id" not in ss:
        ss["case_id"] = core.generate_case_id()
    if "evidence_log" not in ss:
        ss["evidence_log"] = []
    if "uploader_key" not in ss:
        ss["uploader_key"] = 0


def reset_session():
    """Button callback: new case ID, empty log, and clear the file uploader."""
    ss = st.session_state
    ss["case_id"] = core.generate_case_id()
    ss["evidence_log"] = []
    ss["uploader_key"] = ss.get("uploader_key", 0) + 1


def add_to_log(record):
    """Button callback: add a snapshot of one analysed file to the evidence log."""
    log = st.session_state["evidence_log"]
    for entry in log:
        if (entry["filename"], entry["sha256"], entry["comparison_status"]) == (
            record["filename"], record["sha256"], record["comparison_status"]
        ):
            return  # already logged - avoid duplicates
    entry = copy.deepcopy(record)
    entry["evidence_id"] = f"EV-{len(log) + 1:03d}"
    entry["logged_at_utc"] = core.now_utc_iso()
    log.append(entry)


def is_logged(record):
    return any(
        (e["filename"], e["sha256"], e["comparison_status"])
        == (record["filename"], record["sha256"], record["comparison_status"])
        for e in st.session_state["evidence_log"]
    )


init_state()

# --------------------------------------------------------------------------
# Disclaimer and limitations (always visible, never hidden)
# --------------------------------------------------------------------------
st.warning("**Important:** " + core.DISCLAIMER)
with st.expander("📌 Limitations & privacy (please read)"):
    for item in core.LIMITATIONS:
        st.markdown("- " + item)
    st.markdown(
        "**Privacy:** files are processed in memory inside this app only. Nothing is sent "
        "to external analysis services, files are not saved to disk, and file contents are "
        "not written to logs. The evidence log below exists only for this session."
    )

# --------------------------------------------------------------------------
# Case details
# --------------------------------------------------------------------------
st.subheader("1 · Case")
st.text_input(
    "Case ID",
    key="case_id",
    max_chars=40,
    help="Letters, digits, '-' and '_' only. A random ID is generated for you.",
)
case_id = core.sanitize_case_id(st.session_state["case_id"]) or "UNSET"

include_gps = st.checkbox(
    "Include GPS location tags in downloaded reports (off by default - location is sensitive)",
    value=False,
)
st.button("🧹 New case / clear session", on_click=reset_session)

# --------------------------------------------------------------------------
# Upload
# --------------------------------------------------------------------------
st.subheader("2 · Upload evidence")
st.caption(
    f"Allowed: {', '.join(core.ALLOWED_EXTENSIONS)} · max {core.MAX_FILE_SIZE_MB} MB per file · "
    f"up to {core.MAX_FILES_PER_BATCH} files at once. Use fictional files for the demo."
)
uploaded_files = st.file_uploader(
    "Choose one or more files",
    type=list(core.ALLOWED_EXTENSIONS),
    accept_multiple_files=True,
    key=f"uploader_{st.session_state['uploader_key']}",
)

# --------------------------------------------------------------------------
# Batch overview: quick, transparent summary before the detailed file tabs
# --------------------------------------------------------------------------
if uploaded_files:
    st.markdown("### 📊 Batch overview")
    valid_summaries = []
    for item in uploaded_files[: core.MAX_FILES_PER_BATCH]:
        raw = item.getvalue()
        safe_name = core.safe_filename(item.name)
        issues = core.validate_upload(safe_name, len(raw))
        if not issues:
            valid_summaries.append({
                "File": safe_name,
                "Size": core.human_size(len(raw)),
                "SHA-256": core.sha256_hex(raw),
            })
    unique_hashes = len({x["SHA-256"] for x in valid_summaries})
    m1, m2, m3 = st.columns(3)
    m1.metric("Files selected", len(uploaded_files))
    m2.metric("Files ready", len(valid_summaries))
    m3.metric("Unique fingerprints", unique_hashes)
    if valid_summaries:
        st.dataframe(
            [{"File": x["File"], "Size": x["Size"], "SHA-256": x["SHA-256"]} for x in valid_summaries],
            use_container_width=True, hide_index=True,
        )
        hash_groups = {}
        for item in valid_summaries:
            hash_groups.setdefault(item["SHA-256"], []).append(item["File"])
        duplicate_groups = [group for group in hash_groups.values() if len(group) > 1]
        if duplicate_groups:
            st.info("Identical file contents detected in this batch: " + "; ".join(", ".join(g) for g in duplicate_groups))
        else:
            st.caption("No byte-identical files were detected in this batch. Different hashes do not explain what changed.")
    st.caption("Batch fingerprints are calculated from the uploaded bytes. Files are not saved by this overview.")


def show_table(rows):
    """Show a two-column Field/Value table (skips empty input)."""
    if rows:
        st.table({"Field": list(rows.keys()), "Value": [str(v) for v in rows.values()]})


def show_result_banner(record):
    """Big, clear MATCH / MISMATCH / INVALID REFERENCE message."""
    status = record["comparison_status"]
    if status == core.STATUS_MATCH:
        st.success(
            "✅ **MATCH** - the calculated hash equals your reference.\n\n"
            "This means byte-level consistency with the reference only. "
            "It does **not** prove the file is authentic or truthful."
        )
    elif status == core.STATUS_MISMATCH:
        st.error(
            "❌ **MISMATCH** - the calculated hash differs from your reference.\n\n"
            + record["comparison_detail"]
        )
    elif status == core.STATUS_INVALID:
        st.warning("⚠️ **INVALID REFERENCE** - " + record["comparison_detail"])
    else:
        st.info("ℹ️ No reference hash entered yet. Paste one above to run a comparison.")


def show_metadata(meta, file_key):
    """Image metadata tab: observed values first, cautions clearly separate."""
    if not meta.get("attempted"):
        st.info("This file was not identified as an image, so no image metadata was read.")
        return
    if not meta.get("readable"):
        st.warning(f"The image could not be read. {meta.get('error')}")
        return

    st.markdown("#### Observed (read directly from the file)")
    show_table({
        "Image format": meta["format"],
        "Dimensions": f"{meta['width']} x {meta['height']} pixels",
        "Colour mode": meta["mode"],
    })

    if meta["exif_present"]:
        if meta["key_fields"]:
            st.markdown("**Key EXIF fields**")
            show_table(meta["key_fields"])
        else:
            st.caption("EXIF exists but none of the commonly used fields are present.")
        if meta["all_fields"]:
            with st.expander(f"All EXIF fields ({len(meta['all_fields'])})"):
                show_table(meta["all_fields"])
    else:
        st.info(
            "No EXIF metadata was found. This is common (many apps strip it) and is "
            "**not** evidence of tampering."
        )

    if meta["gps_present"]:
        st.warning("📍 This file contains GPS location tags. They are sensitive, so they are hidden by default.")
        if st.checkbox("Show GPS tags on screen", key=f"gps_{file_key}"):
            show_table(meta["gps"])

    st.markdown("#### Cautions on interpretation (not findings)")
    for caution in core.METADATA_CAUTIONS:
        st.markdown("- " + caution)


def analyse_file(index, upload):
    """Analyse one uploaded file and draw its section. Never raises to the user."""
    display_name = core.safe_filename(upload.name)
    label = core.markdown_safe(display_name)
    st.markdown(f"### 📄 {label}")

    try:
        data = upload.getvalue()
        problems = core.validate_upload(display_name, len(data))
        if problems:
            st.error("This file cannot be analysed: " + " ".join(problems))
            return

        file_key = f"{st.session_state['uploader_key']}_{index}_{len(data)}_{display_name}"
        sha = core.sha256_hex(data)

        tab_integrity, tab_meta, tab_report = st.tabs(["🔐 Integrity", "🖼️ Metadata", "📥 Report"])

        with tab_integrity:
            st.markdown("**Calculated SHA-256**")
            st.code(sha, language=None)
            reference = st.text_input(
                "Reference SHA-256 (from your trusted source)",
                key=f"ref_{file_key}",
                placeholder="Paste the 64-character reference hash",
            )
            record = core.build_record(
                case_id, display_name, data, upload.type, reference, sha256_value=sha
            )
            show_result_banner(record)

            st.markdown("**File details** (observed)")
            show_table({
                "File name": record["filename"],
                "Size": f"{core.human_size(record['size_bytes'])} ({record['size_bytes']} bytes)",
                "MIME type (declared by browser)": record["mime_declared_by_browser"],
                "MIME type (guessed from extension)": record["mime_guessed_from_extension"],
                "Type (from content signature)": record["type_from_content_signature"],
                "Analysis time (UTC)": record["analyzed_at_utc"],
                "Case ID": record["case_id"],
            })
            if record["extension_observation"]:
                st.warning(
                    "Observation: " + record["extension_observation"]
                    + " This can be harmless (a renamed file) but is worth noting."
                )

        with tab_meta:
            show_metadata(record["image_metadata"], file_key)

        with tab_report:
            txt_report = core.render_txt_report(case_id, [record], include_gps)
            json_report = core.render_json_report(case_id, [record], include_gps)
            stem = f"{record['case_id']}_{sha[:8]}"
            col_a, col_b = st.columns(2)
            with col_a:
                st.download_button(
                    "⬇️ Report (TXT)", txt_report, file_name=f"{stem}_report.txt",
                    mime="text/plain", key=f"txt_{file_key}",
                )
            with col_b:
                st.download_button(
                    "⬇️ Report (JSON)", json_report, file_name=f"{stem}_report.json",
                    mime="application/json", key=f"json_{file_key}",
                )
            st.button(
                "✅ Already in evidence log" if is_logged(record) else "➕ Add to evidence log",
                key=f"log_{file_key}",
                on_click=add_to_log,
                args=(record,),
                disabled=is_logged(record),
            )
            st.caption("The log entry records the result shown at the moment you add it.")

    except Exception as exc:  # safety net: one bad file must not crash the app
        # Only the error TYPE is shown - never file contents.
        st.error(f"Something went wrong while analysing this file ({type(exc).__name__}). "
                 "It was skipped. Please try another file.")


if uploaded_files:
    if len(uploaded_files) > core.MAX_FILES_PER_BATCH:
        st.warning(
            f"Only the first {core.MAX_FILES_PER_BATCH} files are analysed. "
            "Remove some files or start a new batch."
        )
    for i, up in enumerate(uploaded_files[: core.MAX_FILES_PER_BATCH]):
        analyse_file(i, up)
        st.divider()
else:
    st.info("Upload a file to begin. No file? See the **Testing with fictional evidence** section in the README.")

# --------------------------------------------------------------------------
# Evidence log (current session only)
# --------------------------------------------------------------------------
st.subheader("3 · Evidence log (this session only)")
st.caption("Session tracking is a convenience log, not a tamper-proof chain-of-custody system. Download the case report before ending your session.")
log = st.session_state["evidence_log"]
if not log:
    st.caption("The log is empty. Use “Add to evidence log” in a file's Report tab.")
else:
    st.dataframe(
        [
            {
                "ID": e["evidence_id"],
                "File": e["filename"],
                "SHA-256 (first 16)": e["sha256"][:16],
                "Result": e["comparison_status"],
                "Logged (UTC)": e["logged_at_utc"],
            }
            for e in log
        ],
        use_container_width=True,
        hide_index=True,
    )
    col_c, col_d = st.columns(2)
    with col_c:
        st.download_button(
            "⬇️ Case report (TXT)", core.render_txt_report(case_id, log, include_gps),
            file_name=f"{case_id}_case_report.txt", mime="text/plain", key="case_txt",
        )
    with col_d:
        st.download_button(
            "⬇️ Case report (JSON)", core.render_json_report(case_id, log, include_gps),
            file_name=f"{case_id}_case_report.json", mime="application/json", key="case_json",
        )
    st.caption(
        "The log is held in memory for this session only. Refreshing or closing the page "
        "clears it, so download your reports to keep a copy."
    )

st.divider()
st.caption(
    f"{core.APP_NAME} v{core.APP_VERSION} · Hackathon prototype, not a certified forensic tool · "
    "No evidence is uploaded to external services or stored permanently."
)

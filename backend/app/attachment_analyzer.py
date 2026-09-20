import hashlib
import io
import os
import re
import zipfile
from typing import Any


# ============================================================
# SUPPORTED ATTACHMENT TYPES
# ============================================================

SUPPORTED_EXTENSIONS = {
    ".pdf",
    ".doc",
    ".docx",
    ".docm",
    ".word",
    ".xls",
    ".xlsx",
    ".xlsm",
    ".apk",
    ".exe",
    ".dat",
}


# Explicit ZeroGuard security policy.
# JADX is legitimate software, but the project requirement is
# to quarantine an attachment specifically named jadx.exe.
EXACT_BLOCKED_NAMES = {
    "jadx.exe"
}


# ============================================================
# FILE SIGNATURES
# ============================================================

PE_MAGIC = b"MZ"
PDF_MAGIC = b"%PDF-"
ZIP_MAGIC = b"PK\x03\x04"

OLE_MAGIC = bytes.fromhex(
    "D0CF11E0A1B11AE1"
)


# ============================================================
# RISK LEVEL
# ============================================================

def _severity(score: int) -> str:
    """
    ZeroGuard risk thresholds:

    0 - 29   LOW
    30 - 49  MEDIUM
    50 - 69  HIGH
    70 - 100 CRITICAL
    """

    if score >= 70:
        return "CRITICAL"

    if score >= 50:
        return "HIGH"

    if score >= 30:
        return "MEDIUM"

    return "LOW"


def _add(
    finding_list: list[str],
    score: int,
    points: int,
    reason: str
) -> int:

    finding_list.append(reason)

    return min(
        100,
        score + points
    )


# ============================================================
# ZIP / CONTAINER CHECK
# ============================================================

def _looks_like_zip(data: bytes) -> bool:

    return (
        data.startswith(ZIP_MAGIC)
        or data.startswith(b"PK\x05\x06")
        or data.startswith(b"PK\x07\x08")
    )


# ============================================================
# DOUBLE EXTENSION CHECK
# ============================================================

def _has_suspicious_double_extension(filename: str) -> bool:

    return bool(
        re.search(
            r"\.(pdf|docx?|docm|word|xlsx?|xlsm|apk|dat)\."
            r"(exe|scr|com|bat|cmd|js|vbs|msi)$",
            filename.lower()
        )
    )


# ============================================================
# MAIN ATTACHMENT ANALYZER
# ============================================================

def analyze_attachment(
    filename: str,
    data: bytes,
    mime_type: str = ""
) -> dict[str, Any]:

    name = os.path.basename(
        filename or "unknown"
    )

    lower_name = name.lower()

    ext = os.path.splitext(
        lower_name
    )[1]

    findings: list[str] = []

    score = 0

    # --------------------------------------------------------
    # HASH
    # --------------------------------------------------------

    sha256 = hashlib.sha256(
        data
    ).hexdigest()

    # --------------------------------------------------------
    # UNSUPPORTED FILE TYPE
    # --------------------------------------------------------

    if ext not in SUPPORTED_EXTENSIONS:

        return {
            "filename": name,
            "extension": ext,
            "supported": False,
            "risk_score": 0,
            "risk_level": "LOW",
            "findings": [],
            "sha256": sha256,
            "action": "ALLOW",
        }

    # ========================================================
    # 1. EXPLICIT JADX.EXE POLICY
    # ========================================================

    if lower_name in EXACT_BLOCKED_NAMES:

        score = _add(
            findings,
            score,
            100,
            "Blocked filename policy: jadx.exe"
        )

    # ========================================================
    # 2. DOUBLE EXTENSION / DISGUISED EXECUTABLE
    # ========================================================

    if _has_suspicious_double_extension(
        lower_name
    ):

        score = _add(
            findings,
            score,
            90,
            "Executable or script disguised with a document/archive extension"
        )

    # ========================================================
    # 3. PE EXECUTABLE DETECTION
    # ========================================================

    is_pe = data.startswith(
        PE_MAGIC
    )

    # Example:
    # malicious.dat containing MZ
    # malicious.pdf containing MZ
    # malicious.docx containing MZ

    if is_pe and ext != ".exe":

        score = _add(
            findings,
            score,
            80,
            "Windows PE executable signature detected in a non-executable attachment"
        )

    # ========================================================
    # 4. EXE FILE
    # ========================================================

    if ext == ".exe":

        if is_pe:

            score = _add(
                findings,
                score,
                50,
                "Windows PE executable attachment"
            )

        else:

            score = _add(
                findings,
                score,
                35,
                "File is named .exe but does not have a normal PE header"
            )

    # ========================================================
    # 5. PDF ANALYSIS
    # ========================================================

    if ext == ".pdf":

        if not data.startswith(
            PDF_MAGIC
        ):

            score = _add(
                findings,
                score,
                45,
                "PDF extension does not match a PDF file signature"
            )

        else:

            # Limit inspection to avoid huge memory processing.
            sample = data[
                :20 * 1024 * 1024
            ].lower()

            # JavaScript
            if (
                b"/javascript" in sample
                or b"/js" in sample
            ):

                score = _add(
                    findings,
                    score,
                    50,
                    "PDF contains JavaScript indicators"
                )

            # Automatic action
            if b"/openaction" in sample:

                score = _add(
                    findings,
                    score,
                    50,
                    "PDF contains an automatic OpenAction"
                )

            # Launch external program
            if b"/launch" in sample:

                score = _add(
                    findings,
                    score,
                    55,
                    "PDF contains a Launch action indicator"
                )

            # Embedded files
            if (
                b"/embeddedfile" in sample
                or b"/filespec" in sample
            ):

                score = _add(
                    findings,
                    score,
                    20,
                    "PDF contains embedded-file indicators"
                )

    # ========================================================
    # 6. MODERN OFFICE DOCUMENTS
    # ========================================================

    if ext in {
        ".docx",
        ".docm",
        ".xlsx",
        ".xlsm",
    }:

        if _looks_like_zip(data):

            try:

                with zipfile.ZipFile(
                    io.BytesIO(data)
                ) as z:

                    names = {
                        n.lower()
                        for n in z.namelist()
                    }

                    # VBA macro
                    if any(
                        n.endswith(
                            "vbaproject.bin"
                        )
                        for n in names
                    ):

                        score = _add(
                            findings,
                            score,
                            55,
                            "Office document contains a VBA macro project"
                        )

                    # Embedded objects
                    if any(
                        "embeddings/" in n
                        for n in names
                    ):

                        score = _add(
                            findings,
                            score,
                            25,
                            "Office document contains embedded objects"
                        )

                    # OLE objects
                    if any(
                        "oleobject" in n
                        for n in names
                    ):

                        score = _add(
                            findings,
                            score,
                            30,
                            "Office document contains OLE object indicators"
                        )

            except zipfile.BadZipFile:

                score = _add(
                    findings,
                    score,
                    45,
                    "Office file is not a valid OOXML container"
                )

        else:

            score = _add(
                findings,
                score,
                35,
                "Office extension does not match a valid OOXML ZIP container"
            )

    # ========================================================
    # 7. LEGACY WORD / EXCEL
    # ========================================================

    if ext in {
        ".doc",
        ".word",
        ".xls",
    }:

        if data.startswith(
            OLE_MAGIC
        ):

            sample = data[
                :10 * 1024 * 1024
            ].lower()

            # Macro indicators
            if b"vba" in sample:

                score = _add(
                    findings,
                    score,
                    55,
                    "Legacy Office file contains VBA macro indicators"
                )

            # OLE object
            if b"oleobject" in sample:

                score = _add(
                    findings,
                    score,
                    30,
                    "Legacy Office file contains OLE object indicators"
                )

            # PowerShell
            if b"powershell" in sample:

                score = _add(
                    findings,
                    score,
                    60,
                    "Legacy Office file contains PowerShell indicators"
                )

        else:

            score = _add(
                findings,
                score,
                35,
                "Legacy Office extension does not match an OLE document signature"
            )

    # ========================================================
    # 8. APK ANALYSIS
    # ========================================================

    if ext == ".apk":

        if not _looks_like_zip(data):

            score = _add(
                findings,
                score,
                55,
                "APK extension does not match an Android ZIP package"
            )

        else:

            try:

                with zipfile.ZipFile(
                    io.BytesIO(data)
                ) as z:

                    names = {
                        n.lower()
                        for n in z.namelist()
                    }

                    # AndroidManifest is expected
                    if "androidmanifest.xml" not in names:

                        score = _add(
                            findings,
                            score,
                            45,
                            "APK is missing AndroidManifest.xml"
                        )

                    # DEX code
                    if any(
                        n.endswith(".dex")
                        for n in names
                    ):

                        findings.append(
                            "Android DEX code present"
                        )

                    # Native libraries
                    if any(
                        n.endswith(".so")
                        for n in names
                    ):

                        findings.append(
                            "Native Android library present"
                        )

            except zipfile.BadZipFile:

                score = _add(
                    findings,
                    score,
                    55,
                    "APK is not a valid ZIP package"
                )

    # ========================================================
    # 9. DAT FILE
    # ========================================================

    if ext == ".dat":

        # DAT itself is not malware.
        # We inspect the actual content.

        if is_pe:

            score = _add(
                findings,
                score,
                90,
                "DAT attachment contains a Windows PE executable"
            )

        # Check for suspicious script/executable indicators
        else:

            sample = data[
                :5 * 1024 * 1024
            ].lower()

            suspicious_patterns = [
                b"powershell",
                b"cmd.exe",
                b"wscript",
                b"cscript",
                b"mshta",
            ]

            detected = [
                pattern.decode(
                    errors="ignore"
                )
                for pattern in suspicious_patterns
                if pattern in sample
            ]

            if detected:

                score = _add(
                    findings,
                    score,
                    60,
                    "DAT file contains suspicious script/execution indicators: "
                    + ", ".join(detected)
                )

    # ========================================================
    # 10. FINAL RESULT
    # ========================================================

    level = _severity(
        score
    )

    if level in {
        "HIGH",
        "CRITICAL",
    }:

        action = "QUARANTINE"

    else:

        action = "ALLOW"

    return {
        "filename": name,
        "extension": ext,
        "mime_type": mime_type or "",
        "supported": True,
        "risk_score": score,
        "risk_level": level,
        "findings": findings,
        "sha256": sha256,
        "action": action,
    }


# ============================================================
# MULTIPLE ATTACHMENTS
# ============================================================

def analyze_attachments(
    attachments: list[dict]
) -> dict[str, Any]:

    results = []

    highest_score = 0

    highest_level = "LOW"

    risk_order = {
        "LOW": 0,
        "MEDIUM": 1,
        "HIGH": 2,
        "CRITICAL": 3,
    }

    for attachment in attachments or []:

        result = analyze_attachment(
            attachment.get(
                "filename",
                "unknown"
            ),
            attachment.get(
                "data",
                b""
            ),
            attachment.get(
                "mime_type",
                ""
            ),
        )

        results.append(
            result
        )

        if result["risk_score"] > highest_score:

            highest_score = result[
                "risk_score"
            ]

        if risk_order.get(
            result["risk_level"],
            0
        ) > risk_order.get(
            highest_level,
            0
        ):

            highest_level = result[
                "risk_level"
            ]

    return {
        "attachment_count": len(
            attachments or []
        ),
        "risk_score": highest_score,
        "risk_level": highest_level,
        "quarantine_required": (
            highest_level
            in {"HIGH", "CRITICAL"}
        ),
        "attachments": results,
    }
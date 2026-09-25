from fastapi import FastAPI, File, UploadFile
from fastapi.responses import HTMLResponse
from pathlib import Path
import tempfile
import html
import shutil

from depcheck.cli import scan_file


app = FastAPI(
    title="DepCheck",
    description="Dependency Vulnerability Checker",
    version="1.0.0",
)


# ============================================================
# MAIN PAGE
# ============================================================

HTML_PAGE = """
<!DOCTYPE html>

<html lang="en">

<head>

    <meta charset="UTF-8">

    <meta
        name="viewport"
        content="width=device-width, initial-scale=1.0"
    >

    <title>DepCheck — Dependency Security</title>

    <style>

        @import url(
            'https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700&family=Playfair+Display:wght@500;600&display=swap'
        );

        * {
            box-sizing: border-box;
        }

        :root {
            --bg: #f5f0e8;
            --surface: #fffdf8;
            --surface-soft: #faf7f0;
            --text: #24231f;
            --muted: #777269;
            --border: #e4ddd1;

            --sage: #71856f;
            --sage-light: #e7eee5;

            --terracotta: #b86f52;
            --terracotta-light: #f3e2da;

            --critical: #a94b45;
            --critical-light: #f5dfdc;

            --high: #b76a43;
            --high-light: #f4e4d8;

            --medium: #a1813d;
            --medium-light: #f3ecd9;

            --low: #71856f;
            --low-light: #e5eee4;

            --shadow:
                0 18px 50px rgba(72, 61, 46, 0.08);

            --shadow-small:
                0 8px 24px rgba(72, 61, 46, 0.07);

            --radius: 22px;
        }

        html {
            scroll-behavior: smooth;
        }

        body {
            margin: 0;
            background:
                radial-gradient(
                    circle at 8% 10%,
                    rgba(184, 111, 82, 0.08),
                    transparent 28%
                ),
                radial-gradient(
                    circle at 92% 30%,
                    rgba(113, 133, 111, 0.09),
                    transparent 30%
                ),
                var(--bg);

            color: var(--text);

            font-family:
                "DM Sans",
                Arial,
                sans-serif;

            min-height: 100vh;
        }

        body::before {
            content: "";

            position: fixed;

            inset: 0;

            pointer-events: none;

            opacity: 0.18;

            background-image:
                radial-gradient(
                    rgba(36, 35, 31, 0.12) 0.6px,
                    transparent 0.6px
                );

            background-size: 7px 7px;

            mask-image:
                linear-gradient(
                    to bottom,
                    black,
                    transparent 80%
                );

            z-index: -1;
        }

        a {
            color: inherit;
        }

        .container {
            width: min(
                1120px,
                calc(100% - 40px)
            );

            margin: 0 auto;
        }

        /* ====================================================
           NAVBAR
           ==================================================== */

        .navbar {
            display: flex;

            align-items: center;

            justify-content: space-between;

            padding: 28px 0 20px;
        }

        .brand {
            display: flex;

            align-items: center;

            gap: 11px;

            text-decoration: none;
        }

        .brand-mark {
            width: 38px;
            height: 38px;

            border-radius: 12px;

            display: flex;

            align-items: center;

            justify-content: center;

            background: var(--text);

            color: var(--bg);

            font-size: 17px;

            box-shadow:
                0 6px 16px
                rgba(36, 35, 31, 0.14);
        }

        .brand-name {
            font-size: 18px;

            font-weight: 700;

            letter-spacing: -0.5px;
        }

        .nav-status {
            display: flex;

            align-items: center;

            gap: 8px;

            color: var(--muted);

            font-size: 13px;
        }

        .status-dot {
            width: 7px;
            height: 7px;

            border-radius: 50%;

            background: var(--sage);

            box-shadow:
                0 0 0 4px var(--sage-light);
        }

        /* ====================================================
           HERO
           ==================================================== */

        .hero {
            padding: 62px 0 42px;

            text-align: center;
        }

        .eyebrow {
            display: inline-flex;

            align-items: center;

            gap: 8px;

            padding: 7px 12px;

            border: 1px solid var(--border);

            border-radius: 999px;

            background:
                rgba(255, 253, 248, 0.72);

            color: var(--muted);

            font-size: 12px;

            font-weight: 600;

            letter-spacing: 0.4px;

            text-transform: uppercase;
        }

        .hero h1 {
            margin: 22px auto 14px;

            max-width: 800px;

            font-family:
                "Playfair Display",
                Georgia,
                serif;

            font-size:
                clamp(46px, 7vw, 78px);

            line-height: 0.98;

            letter-spacing: -3px;

            font-weight: 600;
        }

        .hero h1 span {
            color: var(--terracotta);
        }

        .hero p {
            max-width: 620px;

            margin: 0 auto;

            color: var(--muted);

            font-size: 16px;

            line-height: 1.75;
        }

        /* ====================================================
           UPLOAD CARD
           ==================================================== */

        .upload-wrapper {
            max-width: 820px;

            margin: 0 auto 80px;
        }

        .upload-card {
            position: relative;

            padding: 10px;

            border-radius: 28px;

            background:
                rgba(255, 253, 248, 0.76);

            border: 1px solid
                rgba(228, 221, 209, 0.95);

            box-shadow: var(--shadow);

            backdrop-filter: blur(12px);
        }

        .upload-area {
            min-height: 390px;

            border:
                1.5px dashed
                #cec4b5;

            border-radius: 21px;

            display: flex;

            flex-direction: column;

            align-items: center;

            justify-content: center;

            padding: 50px 30px;

            transition:
                transform 0.25s ease,
                border-color 0.25s ease,
                background 0.25s ease;
        }

        .upload-area:hover {
            transform: translateY(-2px);

            border-color: var(--terracotta);

            background:
                rgba(250, 247, 240, 0.8);
        }

        .upload-icon {
            width: 68px;
            height: 68px;

            border-radius: 21px;

            display: flex;

            align-items: center;

            justify-content: center;

            background: var(--surface);

            border: 1px solid var(--border);

            box-shadow: var(--shadow-small);

            font-size: 28px;

            margin-bottom: 22px;
        }

        .upload-area h2 {
            margin: 0 0 9px;

            font-size: 23px;

            letter-spacing: -0.6px;
        }

        .upload-area p {
            margin: 0;

            color: var(--muted);

            font-size: 14px;

            text-align: center;

            line-height: 1.7;
        }

        .file-input {
            margin: 24px 0 15px;

            max-width: 100%;

            font-family: inherit;

            font-size: 13px;

            color: var(--muted);
        }

        .file-input::file-selector-button {
            margin-right: 10px;

            border: 1px solid var(--border);

            background: var(--surface);

            color: var(--text);

            border-radius: 10px;

            padding: 10px 15px;

            font-family: inherit;

            font-weight: 600;

            cursor: pointer;
        }

        .scan-button {
            border: none;

            padding: 14px 25px;

            border-radius: 13px;

            background: var(--text);

            color: var(--surface);

            font-family: inherit;

            font-size: 14px;

            font-weight: 700;

            cursor: pointer;

            box-shadow:
                0 8px 20px
                rgba(36, 35, 31, 0.16);

            transition:
                transform 0.2s ease,
                box-shadow 0.2s ease;
        }

        .scan-button:hover {
            transform: translateY(-2px);

            box-shadow:
                0 12px 26px
                rgba(36, 35, 31, 0.2);
        }

        .supported {
            margin-top: 21px !important;

            font-size: 12px !important;

            color: #958d81 !important;
        }

        .supported strong {
            color: var(--muted);
        }

        /* ====================================================
           RESULTS HEADER
           ==================================================== */

        .results-header {
            display: flex;

            align-items: flex-end;

            justify-content: space-between;

            gap: 20px;

            margin: 40px 0 24px;
        }

        .results-header h1 {
            margin: 0 0 5px;

            font-family:
                "Playfair Display",
                Georgia,
                serif;

            font-size: 38px;

            letter-spacing: -1.5px;
        }

        .results-header p {
            margin: 0;

            color: var(--muted);

            font-size: 14px;
        }

        .scan-again {
            display: inline-flex;

            align-items: center;

            gap: 8px;

            text-decoration: none;

            padding: 11px 15px;

            border-radius: 12px;

            border: 1px solid var(--border);

            background: var(--surface);

            font-size: 13px;

            font-weight: 600;

            transition:
                transform 0.2s ease,
                box-shadow 0.2s ease;
        }

        .scan-again:hover {
            transform: translateY(-2px);

            box-shadow: var(--shadow-small);
        }

        /* ====================================================
           SUMMARY
           ==================================================== */

        .summary {
            display: grid;

            grid-template-columns:
                repeat(3, 1fr);

            gap: 15px;

            margin-bottom: 15px;
        }

        .summary-card {
            background: var(--surface);

            border: 1px solid var(--border);

            border-radius: var(--radius);

            padding: 25px;

            box-shadow: var(--shadow-small);

            transition:
                transform 0.2s ease;
        }

        .summary-card:hover {
            transform: translateY(-3px);
        }

        .summary-card .label {
            color: var(--muted);

            font-size: 12px;

            font-weight: 600;

            text-transform: uppercase;

            letter-spacing: 0.8px;
        }

        .summary-card .number {
            margin-top: 11px;

            font-family:
                "Playfair Display",
                Georgia,
                serif;

            font-size: 42px;

            line-height: 1;
        }

        /* ====================================================
           RISK
           ==================================================== */

        .section-label {
            margin: 42px 0 14px;

            color: var(--muted);

            font-size: 11px;

            font-weight: 700;

            text-transform: uppercase;

            letter-spacing: 1.2px;
        }

        .risk-summary {
            display: grid;

            grid-template-columns:
                repeat(4, 1fr);

            gap: 13px;
        }

        .risk-card {
            position: relative;

            background: var(--surface);

            border: 1px solid var(--border);

            border-radius: 18px;

            padding: 19px;

            overflow: hidden;
        }

        .risk-card::after {
            content: "";

            position: absolute;

            width: 70px;
            height: 70px;

            border-radius: 50%;

            right: -28px;
            top: -28px;

            opacity: 0.35;
        }

        .risk-card.critical::after {
            background: var(--critical);
        }

        .risk-card.high::after {
            background: var(--high);
        }

        .risk-card.medium::after {
            background: var(--medium);
        }

        .risk-card.low::after {
            background: var(--low);
        }

        .risk-name {
            color: var(--muted);

            font-size: 12px;

            font-weight: 600;
        }

        .risk-number {
            margin-top: 9px;

            font-size: 28px;

            font-weight: 700;
        }

        /* ====================================================
           FIX FIRST
           ==================================================== */

        .fix-first {
            margin-top: 45px;

            background: var(--text);

            color: var(--surface);

            border-radius: 25px;

            padding: 28px;

            box-shadow: var(--shadow);
        }

        .fix-first-header {
            display: flex;

            align-items: center;

            justify-content: space-between;

            gap: 20px;

            margin-bottom: 18px;
        }

        .fix-first h2 {
            margin: 0;

            font-family:
                "Playfair Display",
                Georgia,
                serif;

            font-size: 27px;

            font-weight: 500;
        }

        .fix-first-description {
            margin: 5px 0 0;

            color: #aaa59b;

            font-size: 13px;
        }

        .fix-item {
            display: flex;

            align-items: center;

            justify-content: space-between;

            gap: 20px;

            padding: 17px 0;

            border-top: 1px solid
                rgba(255,255,255,0.1);
        }

        .fix-item-main {
            min-width: 0;
        }

        .fix-package {
            font-size: 15px;

            font-weight: 700;
        }

        .fix-id {
            margin-top: 5px;

            color: #a7a39b;

            font-size: 12px;
        }

        .fix-version {
            color: #c6c1b8;

            font-size: 12px;

            margin-top: 4px;
        }

        .fix-action {
            flex-shrink: 0;

            padding: 9px 12px;

            border-radius: 9px;

            background: rgba(255,255,255,0.09);

            color: #f1ece4;

            font-size: 11px;

            font-weight: 700;
        }

        /* ====================================================
           BADGES
           ==================================================== */

        .badge {
            display: inline-flex;

            align-items: center;

            padding: 5px 9px;

            border-radius: 999px;

            font-size: 10px;

            font-weight: 800;

            text-transform: uppercase;

            letter-spacing: 0.5px;
        }

        .badge-critical {
            background: var(--critical-light);

            color: var(--critical);
        }

        .badge-high {
            background: var(--high-light);

            color: var(--high);
        }

        .badge-medium {
            background: var(--medium-light);

            color: var(--medium);
        }

        .badge-low {
            background: var(--low-light);

            color: var(--low);
        }

        .badge-unknown {
            background: #eeeae2;

            color: #777269;
        }

        /* ====================================================
           DEPENDENCY
           ==================================================== */

        .dependency-list {
            margin-top: 25px;
        }

        .dependency {
            background: var(--surface);

            border: 1px solid var(--border);

            border-radius: 22px;

            margin-bottom: 16px;

            overflow: hidden;

            box-shadow: var(--shadow-small);
        }

        .dependency-header {
            padding: 22px 24px;

            display: flex;

            align-items: center;

            justify-content: space-between;

            gap: 20px;
        }

        .dependency-name {
            font-size: 17px;

            font-weight: 700;
        }

        .dependency-version {
            margin-top: 4px;

            color: var(--muted);

            font-size: 12px;
        }

        .safe-state {
            display: inline-flex;

            align-items: center;

            gap: 8px;

            padding: 8px 11px;

            background: var(--sage-light);

            color: var(--sage);

            border-radius: 999px;

            font-size: 11px;

            font-weight: 700;
        }

        .safe-dot {
            width: 6px;
            height: 6px;

            border-radius: 50%;

            background: var(--sage);
        }

        /* ====================================================
           VULNERABILITY
           ==================================================== */

        .vulnerability {
            margin: 0 18px 18px;

            border: 1px solid var(--border);

            border-radius: 17px;

            overflow: hidden;

            background: var(--surface-soft);
        }

        .vulnerability-top {
            padding: 20px;

            border-left: 4px solid var(--terracotta);
        }

        .vulnerability.critical
        .vulnerability-top {
            border-left-color: var(--critical);
        }

        .vulnerability.high
        .vulnerability-top {
            border-left-color: var(--high);
        }

        .vulnerability.medium
        .vulnerability-top {
            border-left-color: var(--medium);
        }

        .vulnerability.low
        .vulnerability-top {
            border-left-color: var(--low);
        }

        .vulnerability-heading {
            display: flex;

            align-items: center;

            justify-content: space-between;

            gap: 15px;

            margin-bottom: 11px;
        }

        .vulnerability-id {
            font-size: 14px;

            font-weight: 800;

            word-break: break-word;
        }

        .vulnerability-summary {
            color: #5f5a51;

            font-size: 14px;

            line-height: 1.65;
        }

        .vulnerability-meta {
            display: flex;

            flex-wrap: wrap;

            gap: 9px;

            margin-top: 15px;
        }

        .meta-pill {
            padding: 7px 10px;

            border-radius: 8px;

            background: #f0ebe2;

            color: #696359;

            font-size: 11px;
        }

        .meta-pill strong {
            color: var(--text);
        }

        .details {
            padding: 0 20px 20px;
        }

        .details-inner {
            padding-top: 17px;

            border-top: 1px solid var(--border);
        }

        .details-title {
            margin-bottom: 8px;

            color: var(--text);

            font-size: 12px;

            font-weight: 800;

            text-transform: uppercase;

            letter-spacing: 0.6px;
        }

        .details-text {
            color: var(--muted);

            line-height: 1.7;

            font-size: 13px;

            white-space: pre-wrap;
        }

        .intel-grid {
            display: grid;

            grid-template-columns:
                repeat(2, 1fr);

            gap: 10px;

            margin-top: 15px;
        }

        .intel-box {
            padding: 13px;

            background: #f5f0e8;

            border: 1px solid var(--border);

            border-radius: 11px;
        }

        .intel-label {
            color: #999185;

            font-size: 9px;

            text-transform: uppercase;

            letter-spacing: 0.7px;

            font-weight: 700;

            margin-bottom: 6px;
        }

        .intel-value {
            color: #49453e;

            font-size: 12px;

            line-height: 1.5;

            word-break: break-word;
        }

        .alias-list {
            display: flex;

            flex-wrap: wrap;

            gap: 5px;
        }

        .alias {
            background: #ebe5db;

            border-radius: 6px;

            padding: 4px 7px;

            font-size: 10px;
        }

        .affected-list {
            display: flex;

            flex-wrap: wrap;

            gap: 5px;
        }

        .affected-version {
            background: #ebe5db;

            color: #686158;

            padding: 4px 7px;

            border-radius: 6px;

            font-size: 10px;
        }

        .reference-list {
            margin: 8px 0 0;

            padding-left: 17px;
        }

        .reference-list li {
            margin: 6px 0;

            color: var(--muted);

            font-size: 12px;
        }

        .reference-list a {
            color: var(--terracotta);

            text-decoration: none;

            word-break: break-all;
        }

        .reference-list a:hover {
            text-decoration: underline;
        }

        .recommendation {
            margin-top: 16px;

            padding: 14px;

            background: var(--sage-light);

            border: 1px solid #d4e2d2;

            border-radius: 11px;

            color: #526450;

            font-size: 13px;

            line-height: 1.6;
        }

        .recommendation-title {
            color: var(--sage);

            font-size: 11px;

            font-weight: 800;

            text-transform: uppercase;

            letter-spacing: 0.5px;

            margin-bottom: 5px;
        }

        /* ====================================================
           SKIPPED
           ==================================================== */

        .skipped {
            margin: 40px 0;

            background: #fbf5e9;

            border: 1px solid #eadfca;

            border-radius: 20px;

            padding: 24px;
        }

        .skipped h2 {
            margin: 0 0 15px;

            font-family:
                "Playfair Display",
                Georgia,
                serif;

            font-size: 24px;
        }

        .skipped p {
            padding: 13px;

            margin: 8px 0;

            background: rgba(
                255,
                255,
                255,
                0.5
            );

            border-radius: 9px;

            color: var(--muted);

            font-size: 12px;

            line-height: 1.6;
        }

        /* ====================================================
           EMPTY / ERROR
           ==================================================== */

        .error {
            max-width: 700px;

            margin: 70px auto;

            padding: 24px;

            border-radius: 18px;

            background: var(--critical-light);

            border: 1px solid #e8c9c5;

            color: #82443f;

            box-shadow: var(--shadow-small);
        }

        .no-vulnerabilities {
            margin: 0 18px 18px;

            padding: 17px;

            border-radius: 14px;

            background: var(--sage-light);

            color: var(--sage);

            font-size: 13px;

            font-weight: 600;
        }

        .empty-value {
            color: #aaa298;
        }

        /* ====================================================
           FOOTER
           ==================================================== */

        .footer {
            margin-top: 80px;

            padding: 30px 0 45px;

            border-top: 1px solid var(--border);

            display: flex;

            align-items: center;

            justify-content: space-between;

            gap: 20px;

            color: #948c80;

            font-size: 12px;
        }

        .footer strong {
            color: var(--text);
        }

        /* ====================================================
           RESPONSIVE
           ==================================================== */

        @media (max-width: 760px) {

            .container {
                width:
                    calc(100% - 28px);
            }

            .navbar {
                padding-top: 18px;
            }

            .nav-status {
                display: none;
            }

            .hero {
                padding-top: 45px;
            }

            .hero h1 {
                letter-spacing: -2px;
            }

            .upload-area {
                min-height: 350px;

                padding: 35px 20px;
            }

            .summary {
                grid-template-columns: 1fr;
            }

            .risk-summary {
                grid-template-columns:
                    repeat(2, 1fr);
            }

            .results-header {
                align-items: flex-start;

                flex-direction: column;
            }

            .fix-item {
                align-items: flex-start;

                flex-direction: column;
            }

            .dependency-header {
                align-items: flex-start;

                flex-direction: column;
            }

            .vulnerability-heading {
                align-items: flex-start;

                flex-direction: column;
            }

            .intel-grid {
                grid-template-columns: 1fr;
            }

            .footer {
                align-items: flex-start;

                flex-direction: column;
            }
        }

    </style>

</head>


<body>


<div class="container">


    <!-- =====================================================
         NAVBAR
         ===================================================== -->

    <nav class="navbar">

        <a
            href="/"
            class="brand"
        >

            <div class="brand-mark">
                ◈
            </div>

            <div class="brand-name">
                DepCheck
            </div>

        </a>

        <div class="nav-status">

            <span class="status-dot"></span>

            Security scanner online

        </div>

    </nav>


    __CONTENT__


    <!-- =====================================================
         FOOTER
         ===================================================== -->

    <footer class="footer">

        <div>

            <strong>DepCheck</strong>

            · Dependency security made simple.

        </div>

        <div>

            Vulnerability data powered by OSV.dev

        </div>

    </footer>


</div>


</body>

</html>
"""


# ============================================================
# HOME PAGE
# ============================================================

HOME_CONTENT = """

<section class="hero">

    <div class="eyebrow">

        ◉ Dependency security

    </div>

    <h1>

        Know what's hiding
        <span>inside.</span>

    </h1>

    <p>

        Scan your Python dependencies for known
        vulnerabilities and understand exactly
        what needs attention.

    </p>

</section>


<div class="upload-wrapper">

    <div class="upload-card">

        <form
            action="/scan"
            method="post"
            enctype="multipart/form-data"
        >

            <div class="upload-area">

                <div class="upload-icon">
                    ↑
                </div>

                <h2>
                    Scan your dependency file
                </h2>

                <p>
                    Choose a dependency file from your project
                    and let DepCheck analyse it.
                </p>

                <input
                    class="file-input"
                    type="file"
                    name="file"
                    accept=".txt,.toml,.lock"
                    required
                >

                <button
                    class="scan-button"
                    type="submit"
                >

                    Scan dependencies →

                </button>

                <p class="supported">

                    <strong>Supported:</strong>

                    requirements.txt ·
                    pyproject.toml ·
                    Pipfile ·
                    Pipfile.lock ·
                    poetry.lock

                </p>

            </div>

        </form>

    </div>

</div>

"""


# ============================================================
# HELPERS
# ============================================================

def safe_text(
    value,
    default="Not available"
):

    if value is None:
        return default

    value = str(value).strip()

    if not value:
        return default

    return html.escape(value)


def render_aliases(aliases):

    if not aliases:

        return """
        <span class="empty-value">
            No aliases available
        </span>
        """

    output = '<div class="alias-list">'

    for alias in aliases:

        output += (
            '<span class="alias">'
            f'{safe_text(alias)}'
            '</span>'
        )

    output += "</div>"

    return output


def render_affected_versions(versions):

    if not versions:

        return """
        <span class="empty-value">
            No specific affected versions listed
        </span>
        """

    output = '<div class="affected-list">'

    for version in versions:

        output += (
            '<span class="affected-version">'
            f'{safe_text(version)}'
            '</span>'
        )

    output += "</div>"

    return output


def render_references(references):

    if not references:

        return """
        <span class="empty-value">
            No references available
        </span>
        """

    output = '<ul class="reference-list">'

    for reference in references:

        if not isinstance(
            reference,
            dict
        ):
            continue

        url = reference.get("url")

        if not url:
            continue

        safe_url = html.escape(
            str(url),
            quote=True
        )

        reference_type = safe_text(
            reference.get(
                "type",
                "Reference"
            )
        )

        output += f"""

        <li>

            <strong>
                {reference_type}
            </strong>:

            <a
                href="{safe_url}"
                target="_blank"
                rel="noopener noreferrer"
            >
                {safe_text(url)}
            </a>

        </li>

        """

    output += "</ul>"

    return output


def render_vulnerability_details(
    vulnerability
):

    aliases = render_aliases(
        vulnerability.aliases
    )

    cwe_ids = (

        ", ".join(
            safe_text(cwe)
            for cwe in vulnerability.cwe_ids
        )

        if vulnerability.cwe_ids

        else
        '<span class="empty-value">'
        'No CWE information available'
        '</span>'

    )

    affected_versions = (
        render_affected_versions(
            vulnerability.affected_versions
        )
    )

    affected_ranges = (

        "<br>".join(
            safe_text(item)
            for item in vulnerability.affected_ranges
        )

        if vulnerability.affected_ranges

        else
        '<span class="empty-value">'
        'No affected range information available'
        '</span>'

    )

    references = render_references(
        vulnerability.references
    )

    cvss_vector = safe_text(
        vulnerability.cvss_vector
    )

    details = safe_text(
        vulnerability.details,
        default=(
            "No detailed description available."
        )
    )

    explanation = safe_text(
        vulnerability.explanation,
        default=(
            "No additional explanation available."
        )
    )

    recommendation = safe_text(
        vulnerability.recommendation,
        default=(
            "Review the advisory for "
            "available remediation options."
        )
    )

    return f"""

    <div class="details">

        <div class="details-inner">

            <div class="details-title">
                Security intelligence
            </div>

            <div class="intel-grid">

                <div class="intel-box">

                    <div class="intel-label">
                        CVE / GHSA / Aliases
                    </div>

                    <div class="intel-value">
                        {aliases}
                    </div>

                </div>


                <div class="intel-box">

                    <div class="intel-label">
                        CVSS Vector
                    </div>

                    <div class="intel-value">
                        {cvss_vector}
                    </div>

                </div>


                <div class="intel-box">

                    <div class="intel-label">
                        CWE
                    </div>

                    <div class="intel-value">
                        {cwe_ids}
                    </div>

                </div>


                <div class="intel-box">

                    <div class="intel-label">
                        Affected versions
                    </div>

                    <div class="intel-value">
                        {affected_versions}
                    </div>

                </div>


                <div class="intel-box">

                    <div class="intel-label">
                        Affected ranges
                    </div>

                    <div class="intel-value">
                        {affected_ranges}
                    </div>

                </div>


                <div class="intel-box">

                    <div class="intel-label">
                        Fixed version
                    </div>

                    <div class="intel-value">

                        {safe_text(
                            vulnerability.fixed_version
                        )}

                    </div>

                </div>

            </div>


            <div style="margin-top:20px;">

                <div class="details-title">
                    Vulnerability details
                </div>

                <div class="details-text">
                    {details}
                </div>

            </div>


            <div style="margin-top:20px;">

                <div class="details-title">
                    DepCheck explanation
                </div>

                <div class="details-text">
                    {explanation}
                </div>

            </div>


            <div class="recommendation">

                <div class="recommendation-title">
                    Recommended action
                </div>

                {recommendation}

            </div>


            <div style="margin-top:20px;">

                <div class="details-title">
                    References
                </div>

                {references}

            </div>

        </div>

    </div>

    """


# ============================================================
# HOME ROUTE
# ============================================================

@app.get(
    "/",
    response_class=HTMLResponse
)
async def home():

    page = HTML_PAGE.replace(
        "__CONTENT__",
        HOME_CONTENT
    )

    return HTMLResponse(
        content=page
    )


# ============================================================
# SCAN ROUTE
# ============================================================

@app.post(
    "/scan",
    response_class=HTMLResponse
)
async def scan(
    file: UploadFile = File(...)
):

    temp_path = None

    temp_directory = None

    try:

        # ----------------------------------------------------
        # Validate filename
        # ----------------------------------------------------

        if not file.filename:

            error_message = (
                "No file was selected."
            )

            content = f"""

            <div class="error">

                <strong>
                    Unable to scan
                </strong>

                <p>
                    {html.escape(error_message)}
                </p>

            </div>

            {HOME_CONTENT}

            """

            page = HTML_PAGE.replace(
                "__CONTENT__",
                content
            )

            return HTMLResponse(
                content=page,
                status_code=400
            )


        # ----------------------------------------------------
        # Read uploaded file
        # ----------------------------------------------------

        file_content = await file.read()


        # ----------------------------------------------------
        # Maximum file size
        # ----------------------------------------------------

        MAX_FILE_SIZE = (
            1 * 1024 * 1024
        )

        if len(file_content) > MAX_FILE_SIZE:

            error_message = (
                "File is too large. "
                "Maximum allowed size is 1 MB."
            )

            content = f"""

            <div class="error">

                <strong>
                    File too large
                </strong>

                <p>
                    {html.escape(error_message)}
                </p>

            </div>

            {HOME_CONTENT}

            """

            page = HTML_PAGE.replace(
                "__CONTENT__",
                content
            )

            return HTMLResponse(
                content=page,
                status_code=413
            )


        # ----------------------------------------------------
        # Preserve original filename
        #
        # This is important because the parser selects
        # the parser based on the original filename.
        # ----------------------------------------------------

        original_filename = Path(
            file.filename
        ).name


        # ----------------------------------------------------
        # Create unique temporary directory
        # ----------------------------------------------------

        temp_directory = Path(
            tempfile.mkdtemp(
                prefix="depcheck_"
            )
        )


        # ----------------------------------------------------
        # Preserve exact filename
        # ----------------------------------------------------

        temp_path = (
            temp_directory /
            original_filename
        )


        temp_path.write_bytes(
            file_content
        )


        # ----------------------------------------------------
        # Scan dependency file
        # ----------------------------------------------------

        reports, skipped = scan_file(
            temp_path
        )


        # ----------------------------------------------------
        # Cleanup successful scan
        # ----------------------------------------------------

        if temp_path.exists():

            temp_path.unlink()


        if temp_directory.exists():

            temp_directory.rmdir()


        temp_path = None

        temp_directory = None


        # ====================================================
        # CALCULATE SUMMARY
        # ====================================================

        total_dependencies = len(
            reports
        )

        vulnerable_dependencies = 0

        total_vulnerabilities = 0

        risk_counts = {

            "Critical": 0,
            "High": 0,
            "Medium": 0,
            "Low": 0,
            "Unknown": 0

        }

        all_vulnerabilities = []


        for report in reports:

            vulnerability_count = len(
                report.vulnerabilities
            )

            total_vulnerabilities += (
                vulnerability_count
            )


            if vulnerability_count > 0:

                vulnerable_dependencies += 1


            for vulnerability in (
                report.vulnerabilities
            ):

                risk_level = (
                    vulnerability.risk_level
                )


                if risk_level not in risk_counts:

                    risk_level = "Unknown"


                risk_counts[
                    risk_level
                ] += 1


                all_vulnerabilities.append({

                    "dependency":
                        report.dependency,

                    "vulnerability":
                        vulnerability

                })


        # ====================================================
        # SORT VULNERABILITIES
        # ====================================================

        risk_order = {

            "Critical": 4,
            "High": 3,
            "Medium": 2,
            "Low": 1,
            "Unknown": 0

        }


        all_vulnerabilities.sort(

            key=lambda item:
                risk_order.get(
                    item[
                        "vulnerability"
                    ].risk_level,
                    0
                ),

            reverse=True

        )


        # ====================================================
        # RESULTS HEADER
        # ====================================================

        html_output = f"""

        <div class="results-header">

            <div>

                <h1>
                    Scan complete.
                </h1>

                <p>
                    {safe_text(original_filename)}
                    was analysed successfully.
                </p>

            </div>

            <a
                class="scan-again"
                href="/"
            >

                ↻
                Scan another file

            </a>

        </div>

        """


        # ====================================================
        # SUMMARY CARDS
        # ====================================================

        html_output += f"""

        <div class="summary">

            <div class="summary-card">

                <div class="label">
                    Dependencies scanned
                </div>

                <div class="number">
                    {total_dependencies}
                </div>

            </div>


            <div class="summary-card">

                <div class="label">
                    Vulnerable packages
                </div>

                <div class="number">
                    {vulnerable_dependencies}
                </div>

            </div>


            <div class="summary-card">

                <div class="label">
                    Total vulnerabilities
                </div>

                <div class="number">
                    {total_vulnerabilities}
                </div>

            </div>

        </div>

        """


        # ====================================================
        # SECURITY OVERVIEW
        # ====================================================

        html_output += """

        <div class="section-label">
            Security overview
        </div>

        """


        html_output += f"""

        <div class="risk-summary">

            <div class="risk-card critical">

                <div class="risk-name">
                    Critical
                </div>

                <div class="risk-number">
                    {risk_counts["Critical"]}
                </div>

            </div>


            <div class="risk-card high">

                <div class="risk-name">
                    High
                </div>

                <div class="risk-number">
                    {risk_counts["High"]}
                </div>

            </div>


            <div class="risk-card medium">

                <div class="risk-name">
                    Medium
                </div>

                <div class="risk-number">
                    {risk_counts["Medium"]}
                </div>

            </div>


            <div class="risk-card low">

                <div class="risk-name">
                    Low
                </div>

                <div class="risk-number">
                    {risk_counts["Low"]}
                </div>

            </div>

        </div>

        """


        # ====================================================
        # FIX FIRST
        # ====================================================

        if all_vulnerabilities:

            html_output += """

            <div class="fix-first">

                <div class="fix-first-header">

                    <div>

                        <h2>
                            Fix these first
                        </h2>

                        <p class="fix-first-description">

                            The most important vulnerabilities
                            to investigate first.

                        </p>

                    </div>

                </div>

            """


            for item in all_vulnerabilities[:5]:

                dependency = item[
                    "dependency"
                ]

                vulnerability = item[
                    "vulnerability"
                ]


                dependency_name = safe_text(
                    dependency.name
                )

                dependency_version = safe_text(
                    dependency.version
                )

                vulnerability_id = safe_text(
                    vulnerability.id
                )

                fixed_version = safe_text(

                    vulnerability.fixed_version,

                    default=(
                        "No fixed version available"
                    )

                )

                risk_level = (
                    vulnerability.risk_level
                )


                html_output += f"""

                <div class="fix-item">

                    <div class="fix-item-main">

                        <div class="fix-package">

                            {dependency_name}
                            <span style="color:#999;">
                                {dependency_version}
                            </span>

                        </div>

                        <div class="fix-id">

                            {vulnerability_id}

                        </div>

                        <div class="fix-version">

                            Recommended:
                            {fixed_version}

                        </div>

                    </div>


                    <div class="fix-action">

                        {safe_text(risk_level)}

                    </div>

                </div>

                """


            html_output += """

            </div>

            """


        else:

            html_output += """

            <div
                class="fix-first"
                style="
                    background:#71856f;
                "
            >

                <div class="fix-first-header">

                    <div>

                        <h2>
                            Everything looks clear.
                        </h2>

                        <p class="fix-first-description">

                            No known vulnerabilities were
                            returned for the scanned dependencies.

                        </p>

                    </div>

                </div>

            </div>

            """


        # ====================================================
        # DEPENDENCIES
        # ====================================================

        html_output += """

        <div class="section-label">
            Dependency results
        </div>

        <div class="dependency-list">

        """


        for report in reports:

            dependency_name = safe_text(
                report.dependency.name
            )

            dependency_version = safe_text(
                report.dependency.version
            )


            html_output += f"""

            <div class="dependency">

                <div class="dependency-header">

                    <div>

                        <div class="dependency-name">

                            {dependency_name}

                        </div>

                        <div class="dependency-version">

                            Version
                            {dependency_version}

                        </div>

                    </div>

            """


            if not report.vulnerabilities:

                html_output += """

                    <div class="safe-state">

                        <span class="safe-dot"></span>

                        No known issues

                    </div>

                </div>

                <div class="no-vulnerabilities">

                    ✓ No known vulnerabilities found
                    for this dependency.

                </div>

                """


            else:

                html_output += """

                </div>

                """


                for vulnerability in (
                    report.vulnerabilities
                ):

                    vulnerability_id = safe_text(
                        vulnerability.id
                    )

                    summary = safe_text(
                        vulnerability.summary,
                        default=(
                            "No vulnerability "
                            "summary available."
                        )
                    )

                    severity = safe_text(
                        vulnerability.severity
                    )

                    risk_level = safe_text(
                        vulnerability.risk_level
                    )

                    fixed_version = safe_text(
                        vulnerability.fixed_version,
                        default=(
                            "No fixed version available"
                        )
                    )


                    risk_class = (
                        vulnerability.risk_level
                        .lower()
                    )


                    if risk_class not in [
                        "critical",
                        "high",
                        "medium",
                        "low"
                    ]:

                        risk_class = "unknown"


                    html_output += f"""

                    <div
                        class="
                            vulnerability
                            {risk_class}
                        "
                    >

                        <div class="vulnerability-top">

                            <div class="vulnerability-heading">

                                <div class="vulnerability-id">

                                    {vulnerability_id}

                                </div>

                                <span
                                    class="
                                        badge
                                        badge-{risk_class}
                                    "
                                >

                                    {risk_level}

                                </span>

                            </div>


                            <div class="vulnerability-summary">

                                {summary}

                            </div>


                            <div class="vulnerability-meta">

                                <div class="meta-pill">

                                    Severity:
                                    <strong>
                                        {severity}
                                    </strong>

                                </div>


                                <div class="meta-pill">

                                    Fixed:
                                    <strong>
                                        {fixed_version}
                                    </strong>

                                </div>

                            </div>

                        </div>


                        {
                            render_vulnerability_details(
                                vulnerability
                            )
                        }

                    </div>

                    """


            html_output += """

            </div>

            """


        html_output += """

        </div>

        """


        # ====================================================
        # SKIPPED REQUIREMENTS
        # ====================================================

        if skipped:

            html_output += """

            <div class="skipped">

                <h2>
                    Skipped requirements
                </h2>

                <p>
                    These entries could not be analysed
                    because they did not contain an exact
                    dependency version or used an unsupported
                    requirement format.
                </p>

            """


            for item in skipped:

                line_number = safe_text(
                    item.line
                )

                original_text = safe_text(
                    item.text
                )

                reason = safe_text(
                    item.reason
                )


                html_output += f"""

                <p>

                    <strong>
                        Line {line_number}
                    </strong>

                    · {original_text}

                    <br>

                    Reason:
                    {reason}

                </p>

                """


            html_output += """

            </div>

            """


        # ====================================================
        # FINAL PAGE
        # ====================================================

        page = HTML_PAGE.replace(
            "__CONTENT__",
            html_output
        )


        return HTMLResponse(
            content=page,
            status_code=200
        )


    # ========================================================
    # ERROR HANDLING
    # ========================================================

    except Exception as exc:

        if temp_directory is not None:

            try:

                shutil.rmtree(
                    temp_directory,
                    ignore_errors=True
                )

            except Exception:

                pass

        elif temp_path is not None:

            try:

                if temp_path.exists():

                    temp_path.unlink()

            except Exception:

                pass


        error_message = html.escape(
            str(exc)
        )


        content = f"""

        <div class="error">

            <strong>
                Something went wrong.
            </strong>

            <p>
                {error_message}
            </p>

            <a
                class="scan-again"
                href="/"
            >

                ← Try another file

            </a>

        </div>

        """


        page = HTML_PAGE.replace(
            "__CONTENT__",
            content
        )


        return HTMLResponse(
            content=page,
            status_code=500
        )
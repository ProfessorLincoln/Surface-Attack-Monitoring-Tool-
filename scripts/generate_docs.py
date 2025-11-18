from docx import Document
from docx.shared import Pt
from docx.enum.text import WD_ALIGN_PARAGRAPH


def generate_gantt_docx(path: str = "docs/Gantt.docx"):
    doc = Document()
    doc.add_heading('Gantt Chart - Surface Attack Monitoring Tool', level=1)
    doc.add_paragraph('Timeline: 12 weeks (W1–W12). Adjust as needed.')
    doc.add_paragraph('Legend: ■ = planned work, blank = no work, [M] = milestone')

    # Header row: Task, Start, End, Dur, Depends, W01..W12
    cols = 5 + 12
    table = doc.add_table(rows=1, cols=cols)
    table.style = 'Table Grid'
    hdr = table.rows[0].cells
    headers = ["Task", "Start", "End", "Dur", "Depends"] + [f"W{w:02d}" for w in range(1, 13)]
    for i, h in enumerate(headers):
        p = hdr[i].paragraphs[0]
        run = p.add_run(h)
        p.alignment = WD_ALIGN_PARAGRAPH.CENTER
        run.font.bold = True

    tasks = [
        {"name": "Initiation", "start": 1, "end": 2, "dur": 2, "dep": "-"},
        {"name": "Architecture & Design", "start": 2, "end": 4, "dur": 3, "dep": "Initiation"},
        {"name": "Backend Development", "start": 3, "end": 8, "dur": 6, "dep": "Arch & Design"},
        {"name": "Frontend & UI", "start": 4, "end": 7, "dur": 4, "dep": "Arch, Backend"},
        {"name": "Database & Persistence", "start": 3, "end": 5, "dur": 3, "dep": "Arch & Design"},
        {"name": "Security & Compliance", "start": 5, "end": 9, "dur": 5, "dep": "Backend, DB"},
        {"name": "Testing & QA", "start": 7, "end": 10, "dur": 4, "dep": "Backend, Frontend, Security"},
        {"name": "DevOps & Deployment", "start": 8, "end": 11, "dur": 4, "dep": "Backend, Testing"},
        {"name": "Documentation & Training", "start": 9, "end": 12, "dur": 4, "dep": "Testing, DevOps"},
        {"name": "Project Management", "start": 1, "end": 12, "dur": 12, "dep": "(ongoing)"},
    ]

    for t in tasks:
        cells = table.add_row().cells
        cells[0].text = t["name"]
        cells[1].text = f"W{t['start']}"
        cells[2].text = f"W{t['end']}"
        cells[3].text = str(t["dur"])
        cells[4].text = t["dep"]
        for w in range(1, 13):
            p = cells[4 + w].paragraphs[0]
            run = p.add_run("■" if t["start"] <= w <= t["end"] else "")
            run.font.name = 'Courier New'
            run.font.size = Pt(11)
            p.alignment = WD_ALIGN_PARAGRAPH.CENTER

    doc.add_paragraph("\nNotes:")
    doc.add_paragraph("- Use Courier New in week columns to keep bars aligned.")
    doc.add_paragraph("- Replace W01–W12 with calendar dates as needed.")
    doc.save(path)


def generate_wbs_docx(path: str = "docs/WBS.docx"):
    doc = Document()
    doc.add_heading('Work Breakdown Structure (WBS) - Surface Attack Monitoring Tool', level=1)
    sections = [
        ("1. Initiation", [
            "1.1 Define scope and success criteria",
            "1.2 Identify stakeholders and roles",
            "1.3 Risk and dependency assessment",
            "1.4 Project schedule and milestones",
        ]),
        ("2. Architecture & Design", [
            "2.1 System architecture diagram (Flask + MongoDB + Email + Optional AI)",
            "2.2 Data model design (users, scans, results, logs)",
            "2.3 Security model (sessions, roles, admin)",
            "2.4 WBS and delivery plan approval",
        ]),
        ("3. Backend Development", [
            "3.1 Flask app structure and configuration",
            "3.2 Authentication (register/login, Google OAuth, optional 2FA)",
            "3.3 Admin panel (user management, cascade delete of scans)",
            "3.4 Scan ingestion (VirusTotal and optional ProjectDiscovery)",
            "3.5 Email service (SendGrid/SMTP for OTP and notices)",
            "3.6 Report generation (HTML + PDF via xhtml2pdf)",
            "3.7 API endpoints (scan submission, history, results)",
            "3.8 Error handling and logging",
        ]),
        ("4. Frontend & UI", [
            "4.1 Templates: index, dashboard, results, admin",
            "4.2 Navbar and responsive top-row actions",
            "4.3 Verify/OTP flow UX improvements",
            "4.4 Accessibility and responsive CSS (breakpoints)",
        ]),
        ("5. Database & Persistence", [
            "5.1 MongoDB connection, indexes (e.g., user_id, created_at)",
            "5.2 Data retention policy and cleanup jobs",
            "5.3 Seed data and admin bootstrap",
            "5.4 Backup/restore guidelines",
        ]),
        ("6. Security & Compliance", [
            "6.1 Input validation and sanitization",
            "6.2 Session security, cookies, CSRF",
            "6.3 Secrets management and environment loading",
            "6.4 Audit logging and admin actions",
        ]),
        ("7. Testing & QA", [
            "7.1 Unit tests (email send, cascade delete)",
            "7.2 Integration tests (auth, scans, history)",
            "7.3 Manual UAT checklist",
            "7.4 Performance and load checks",
        ]),
        ("8. DevOps & Deployment", [
            "8.1 Render setup (Procfile, build/start commands)",
            "8.2 Environment variables in Render",
            "8.3 Health checks and monitoring",
            "8.4 Release process and rollback plan",
        ]),
        ("9. Documentation & Training", [
            "9.1 README and setup guide",
            "9.2 Admin handbook",
            "9.3 User guide",
            "9.4 Operations runbook",
        ]),
        ("10. Project Management", [
            "10.1 Standups and status reporting",
            "10.2 Milestone tracking",
            "10.3 Risk review cadence",
            "10.4 Final delivery and retrospective",
        ]),
    ]

    for title, items in sections:
        doc.add_heading(title, level=2)
        for it in items:
            p = doc.add_paragraph(it)
            p.style = doc.styles['List Bullet']

    doc.save(path)


if __name__ == "__main__":
    generate_gantt_docx()
    generate_wbs_docx()
    print("Generated: docs/Gantt.docx and docs/WBS.docx")
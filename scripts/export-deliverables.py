#!/usr/bin/env python3
"""
AuthShield 360 — Export deliverables to PDF / DOCX / PPTX (offline).

Sources (Markdown): docs/technical/*.md and the Arabic guides docs/0*.md,
plus the HTML presentation (presentation/index.html).

Outputs — PDF + DOCX next to every source Markdown:
  docs/technical/Technical_Report_AR|EN.pdf / .docx
  docs/technical/User_and_Role_Access_Matrix.pdf / .docx
  docs/technical/Identity_Security_Test_Matrix.pdf / .docx
  docs/01..04-*.pdf / .docx
  docs/technical/Presentation_Deck.pptx        docs/technical/Presentation_Deck.pdf  (from presentation/index.html)

Requirements: python-docx, python-pptx, markdown; headless Microsoft Edge for PDF.
"""
import html as _html
import base64
import os, re, subprocess, sys, tempfile
from pathlib import Path

if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8', errors='replace')

ROOT = Path(__file__).resolve().parent.parent
EDGE = r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"

# ----------------------------------------------------------------------------
# 1) Lightweight Markdown block parser (headings / tables / lists / code / quote)
# ----------------------------------------------------------------------------
def inline(t):
    t = _html.escape(t)
    t = re.sub(r'`([^`]+)`', r'<code>\1</code>', t)
    t = re.sub(r'\*\*([^*]+)\*\*', r'<b>\1</b>', t)
    t = re.sub(r'\*([^*]+)\*', r'<i>\1</i>', t)
    t = re.sub(r'\[([^\]]+)\]\(([^)]+)\)', r'<a href="\2">\1</a>', t)
    return t

def parse_md(text):
    lines = text.splitlines()
    blocks, i, n = [], 0, len(lines)
    while i < n:
        ln = lines[i]
        if not ln.strip():
            i += 1; continue
        if ln.startswith('```'):
            i += 1; buf = []
            while i < n and not lines[i].startswith('```'):
                buf.append(lines[i]); i += 1
            i += 1
            blocks.append({'type': 'code', 'text': '\n'.join(buf)})
            continue
        m = re.match(r'^(#{1,4})\s+(.*)$', ln)
        if m:
            blocks.append({'type': 'h', 'level': len(m.group(1)), 'text': m.group(2)}); i += 1; continue
        if re.match(r'^\s*---+\s*$', ln):
            blocks.append({'type': 'hr'}); i += 1; continue
        m = re.match(r'^\s*([>-])\s+(.*)$', ln)
        if m and m.group(1) in ('-', '>'):
            kind = 'quote' if m.group(1) == '>' else 'ul'
            if not blocks or blocks[-1]['type'] != kind:
                blocks.append({'type': kind, 'items': []})
            blocks[-1]['items'].append(m.group(2)); i += 1; continue
        m = re.match(r'^\s*(\d+)[.)]\s+(.*)$', ln)
        if m:
            if not blocks or blocks[-1]['type'] != 'ol':
                blocks.append({'type': 'ol', 'items': []})
            blocks[-1]['items'].append(m.group(2)); i += 1; continue
        if ln.lstrip().startswith('|'):
            table, rows = [], []
            while i < n and lines[i].lstrip().startswith('|'):
                row = [c.strip() for c in lines[i].strip().strip('|').split('|')]
                if not all(re.match(r'^:?-+:?$', c) for c in row):
                    rows.append(row)
                i += 1
            blocks.append({'type': 'table', 'rows': rows})
            continue
        # paragraph (may continue while next line is plain)
        buf = [ln]; i += 1
        while i < n and lines[i].strip() and not lines[i].startswith('#') \
                and not lines[i].lstrip().startswith('|') and not lines[i].startswith('```') \
                and not re.match(r'^\s*([>-]|\d+[.)])\s+', lines[i]) and not re.match(r'^\s*---+$', lines[i]):
            buf.append(lines[i]); i += 1
        blocks.append({'type': 'p', 'text': ' '.join(x.strip() for x in buf)})
    return blocks

def blocks_html(blocks, rtl):
    parts = []
    for b in blocks:
        if b['type'] == 'h':
            tag = f"h{b['level']}"; parts.append(f'<{tag}>{inline(b["text"])}</{tag}>')
        elif b['type'] == 'p':
            parts.append(f'<p>{inline(b["text"])}</p>')
        elif b['type'] == 'hr':
            parts.append('<hr/>')
        elif b['type'] == 'code':
            parts.append(f'<pre>{_html.escape(b["text"])}</pre>')
        elif b['type'] in ('ul', 'ol'):
            tag = 'ul' if b['type'] == 'ul' else 'ol'
            parts.append('<' + tag + '>' + ''.join(f'<li>{inline(x)}</li>' for x in b['items']) + '</' + tag + '>')
        elif b['type'] == 'quote':
            parts.append('<blockquote>' + ''.join(f'<p>{inline(x)}</p>' for x in b['items']) + '</blockquote>')
        elif b['type'] == 'table':
            rows = b['rows']
            if not rows: continue
            html = '<table><thead><tr>' + ''.join(f'<th>{inline(c)}</th>' for c in rows[0]) + '</tr></thead><tbody>'
            for r in rows[1:]:
                html += '<tr>' + ''.join(f'<td>{inline(c)}</td>' for c in r) + '</tr>'
            html += '</tbody></table>'
            parts.append(html)
    return '\n'.join(parts)

def doc_html(title, body, rtl, font='Segoe UI'):
    dirattr = ' dir="rtl"' if rtl else ''
    align = 'right' if rtl else 'left'
    return f'''<!doctype html><html{dirattr}><head><meta charset="utf-8">
<title>{_html.escape(title)}</title>
<style>
@page {{ size: A4; margin: 16mm 14mm; }}
body {{ font-family: {font}, Tahoma, sans-serif; font-size: 10.5pt; line-height: 1.55;
       color:#16283b; max-width: 100%; }}
h1 {{ font-size: 20pt; color:#0e7490; border-bottom: 3px solid #0e7490; padding-bottom:6px; }}
h2 {{ font-size: 15pt; color:#155e75; margin-top:22px; border-bottom:1px solid #cbd5e1; }}
h3 {{ font-size: 12.5pt; color:#0f766e; }}
table {{ border-collapse: collapse; width: 100%; margin: 10px 0; }}
th, td {{ border: 1px solid #94a3b8; padding: 4px 7px; font-size: 9pt; }}
th {{ background: #e0f2fe; }}
pre {{ background:#0f172a; color:#e2e8f0; padding:9px; border-radius:6px; font-size:8.5pt;
       white-space: pre-wrap; direction:ltr; text-align:left; }}
code {{ background:#f1f5f9; color:#0f766e; padding:0 3px; border-radius:3px; font-size:9pt; }}
blockquote {{ border-{ 'right' if rtl else 'left' }: 4px solid #38bdf8; margin:8px { '0 0 0' if rtl else '0' }; padding:2px 10px; background:#f0f9ff; }}
hr {{ border:none; border-top:2px dashed #94a3b8; margin:18px 0; }}
ul, ol {{ margin:6px 0; }} li {{ margin:2px 0; }}
a {{ color:#0369a1; }}
p {{ text-align: {align}; }}
header {{ font-size: 9pt; color:#64748b; margin-bottom: 14px; border:1px solid #cbd5e1;
   padding:6px 8px; border-radius:6px; background:#f8fafc; }}
</style></head><body>
<header>AuthShield 360 v2 — دليل التقديم · {_html.escape(title)}</header>
{body}
</body></html>'''

# ----------------------------------------------------------------------------
# 2) DOCX builder (python-docx) preserves RTL + tables + code
# ----------------------------------------------------------------------------
from docx import Document
from docx.shared import Pt, RGBColor, Cm
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.oxml.ns import qn
from docx.oxml import OxmlElement

def _set_font(run, bold=False, mono=False, size=10.5):
    run.font.name = 'Consolas' if mono else 'Segoe UI'
    run._element.rPr.rFonts.set(qn('w:cs'), 'Consolas' if mono else 'Segoe UI')
    run.font.size = Pt(size)
    run.bold = bold
    if (run.font.name == 'Segoe UI'):
        run._element.rPr.rFonts.set(qn('w:eastAsia'), 'Segoe UI')

def _rtl(par, rtl):
    pPr = par._p.get_or_add_pPr()
    if rtl:
        bidi = OxmlElement('w:bidi'); pPr.append(bidi)
    par.alignment = WD_ALIGN_PARAGRAPH.RIGHT if rtl else WD_ALIGN_PARAGRAPH.LEFT

def _text_runs(par, text, rtl, size=10.5):
    # split on ** , * , ` markers
    parts = re.split(r'(\*\*.*?\*\*|\*.*?\*|`[^`]+`)', text)
    for part in parts:
        if not part: continue
        if part.startswith('**'):
            r = par.add_run(part[2:-2]); _set_font(r, bold=True, size=size)
        elif part.startswith('*'):
            r = par.add_run(part[1:-1]); _set_font(r, size=size)
        elif part.startswith('`'):
            r = par.add_run(part[1:-1]); _set_font(r, mono=True, size=size - 1)
        else:
            r = par.add_run(part); _set_font(r, size=size)

def build_docx(blocks, out, rtl, title):
    doc = Document()
    for s in doc.sections:
        s.top_margin, s.bottom_margin, s.left_margin, s.right_margin = Cm(1.7), Cm(1.7), Cm(1.8), Cm(1.8)
    # title
    p = doc.add_paragraph(); _rtl(p, rtl); _text_runs(p, title, rtl, size=18); p.runs[0].bold = True
    for b in blocks:
        if b['type'] == 'h':
            p = doc.add_heading(level=min(b['level'], 4))
            p._p.get_or_add_pPr().remove(p._p.get_or_add_pPr().find(qn('w:pStyle')))
        elif b['type'] == 'p':
            p = doc.add_paragraph(); _rtl(p, rtl); _text_runs(p, b['text'], rtl)
        elif b['type'] == 'hr':
            p = doc.add_paragraph(); _rtl(p, rtl)
        elif b['type'] == 'code':
            p = doc.add_paragraph()
            pPr = p._p.get_or_add_pPr()
            shd = OxmlElement('w:shd'); shd.set(qn('w:val'), 'clear'); shd.set(qn('w:fill'), 'F1F5F9'); pPr.append(shd)
            r = p.add_run(b['text']); _set_font(r, mono=True, size=7.5)
        elif b['type'] in ('ul', 'ol'):
            for it in b['items']:
                p = doc.add_paragraph(style='List Bullet' if b['type'] == 'ul' else 'List Number')
                _rtl(p, rtl); _text_runs(p, it, rtl)
        elif b['type'] == 'quote':
            for it in b['items']:
                p = doc.add_paragraph(); _rtl(p, rtl)
                r = p.add_run(it); _set_font(r, size=10.5)
        elif b['type'] == 'table':
            rows = b['rows']
            if len(rows) < 2: continue
            t = doc.add_table(rows=len(rows), cols=len(rows[0]))
            t.style = 'Table Grid'
            t.alignment = WD_TABLE_ALIGNMENT.RIGHT if rtl else WD_TABLE_ALIGNMENT.LEFT
            for ri, row in enumerate(rows):
                for ci, val in enumerate(row):
                    cell = t.cell(ri, ci)
                    cell.text = ''
                    cp = cell.paragraphs[0]; _rtl(cp, rtl); _text_runs(cp, val, rtl, size=8.5)
                    if ri == 0:
                        for run in cp.runs: run.bold = True
                        shd = OxmlElement('w:shd'); shd.set(qn('w:val'), 'clear'); shd.set(qn('w:fill'), 'E0F2FE'); cell._tc.get_or_add_tcPr().append(shd)
    doc.save(out)

# ----------------------------------------------------------------------------
# 3) PDF via headless Edge
# ----------------------------------------------------------------------------
def render_pdf(html, out):
    tmp = Path(tempfile.gettempdir()) / 'opencode' / (out.stem + '.html')
    tmp.parent.mkdir(parents=True, exist_ok=True)
    tmp.write_text(html, encoding='utf-8')
    uri = tmp.as_uri()
    res = subprocess.run([EDGE, '--headless=new', '--disable-gpu', '--no-pdf-header-footer',
                          '--print-to-pdf=' + str(out), uri], capture_output=True, text=True, timeout=120)
    if not out.exists():
        sys.exit(f'PDF failed for {out.name}: {res.stderr[:300]}')
    tmp.unlink(missing_ok=True)
    print(f'  pdf: {out.name} ({out.stat().st_size//1024} KB)')

# ----------------------------------------------------------------------------
# 4) PPTX deck (python-pptx) — Arabic RTL bullets
# ----------------------------------------------------------------------------
from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN

def _rt(par):
    pPr = par._p.get_or_add_pPr()
    pPr.set('rtl', '1'); par.alignment = PP_ALIGN.RIGHT

def build_pptx(slides, out):
    prs = Presentation()
    prs.slide_width, prs.slide_height = Inches(13.333), Inches(7.5)
    blank = prs.slide_layouts[6]
    title_col, body_col = RGBColor(0x0E, 0x74, 0x90), RGBColor(0x16, 0x28, 0x3B)
    for idx, (kicker, title, items) in enumerate(slides):
        s = prs.slides.add_slide(blank)
        tb = s.shapes.add_textbox(Inches(0.6), Inches(0.42), Inches(12.1), Inches(1.0))
        tf = tb.text_frame; tf.word_wrap = True
        hd = s.shapes.add_textbox(Inches(0.6), Inches(0.12), Inches(12.1), Inches(0.3))
        hf = hd.text_frame; hp = hf.paragraphs[0]; hp.alignment = PP_ALIGN.LEFT
        hr = hp.add_run(); hr.text = 'Cornell Deep  ·  Identity Protection Platform'
        hr.font.size = Pt(11); hr.font.bold = True; hr.font.color.rgb = RGBColor(0x4C, 0x63, 0x77); hr.font.name = 'Segoe UI'
        k = tf.paragraphs[0]; _rt(k); r = k.add_run(); r.text = kicker; r.font.size = Pt(14); r.font.color.rgb = RGBColor(0x1D, 0x4E, 0xD8); r.font.name = 'Segoe UI'
        t = tf.add_paragraph(); _rt(t); r = t.add_run(); r.text = title; r.font.size = Pt(34); r.font.bold = True; r.font.color.rgb = title_col; r.font.name = 'Segoe UI'
        body = s.shapes.add_textbox(Inches(0.6), Inches(1.7), Inches(12.1), Inches(5.4))
        bf = body.text_frame; bf.word_wrap = True
        for i, it in enumerate(items):
            par = bf.paragraphs[0] if i == 0 else bf.add_paragraph(); _rt(par)
            r = par.add_run(); r.text = ('•  ' if not it.startswith('•') else '') + it
            r.font.size = Pt(17 if len(it) < 110 else 15); r.font.color.rgb = body_col; r.font.name = 'Segoe UI'
            par.space_after = Pt(8)
        bar = s.shapes.add_shape(1, Inches(0), Inches(7.18), prs.slide_width, Inches(0.32))
        bar.fill.solid(); bar.fill.fore_color.rgb = title_col; bar.line.fill.background()
    prs.save(out)
    print(f'  pptx: {out.name} ({out.stat().st_size//1024} KB)')

# ----------------------------------------------------------------------------
# MAIN
# ----------------------------------------------------------------------------
def main():
    (ROOT / 'docs' / 'technical').mkdir(parents=True, exist_ok=True)
    docs = [
        (ROOT / 'docs' / 'technical' / 'Technical_Report_AR.md', True),
        (ROOT / 'docs' / 'technical' / 'Technical_Report_EN.md', False),
        (ROOT / 'docs' / 'technical' / 'User_and_Role_Access_Matrix.md', False),
        (ROOT / 'docs' / 'technical' / 'Identity_Security_Test_Matrix.md', False),
        (ROOT / 'docs' / '03-الدليل_الفني_والعلمي.md', True),
        (ROOT / 'docs' / '02-دليل_الاختبار_والتجربة.md', True),
        (ROOT / 'docs' / '04-دليل_تحسين_مستودع_GitHub.md', True),
    ]
    for md, rtl in docs:
        name = md.stem
        print(f'exporting {name} …')
        blocks = parse_md(md.read_text(encoding='utf-8'))
        titles = [b['text'] for b in blocks if b['type'] == 'h']
        title = titles[0] if titles else name
        body = blocks_html(blocks, rtl)
        src_dir = md.parent
        render_pdf(doc_html(title, body, rtl), src_dir / (name + '.pdf'))
        build_docx(blocks, src_dir / (name + '.docx'), rtl, title)
        print(f'  docx: {name}.docx')

    # Deck .pptx (Arabic)
    slides = [
        ('SRS PHASE 2 · IDENTITY PROTECTION', 'منصة حماية الهوية\nمدرسة Cornell Deep',
         ['إصدار v2 — بوابة مدرسية RBAC، تحقيق رقمي، استرداد الحساب، قياس أداء مصادقة',
          'درجة خطر 0–100 لكل محاولة دخول مع أسباب مفسّرة',
          '140 فحصًا آليًا أخضر: smoke 17 · e2e 77 · ui-smoke 28 · restart 18']),
        ('المشكلة', 'لا يكفي «كلمة مرور فقط»',
         ['كلمة المرور تُسرَق أو تُخمَّن',
          'كيف نميّز الدخول الشرعي من المشبوه قبل حدوث الضرر؟',
          'الحل: تقييم سياقي فوري لكل محاولة تسجيل دخول']),
        ('محرك الخطر', 'درجة خطر لحظية لكل محاولة',
         ['F_TIME_ANOMALY +15 · F_NEW_IP +25 · F_NEW_DEVICE +30 · F_IMPOSSIBLE_TRAVEL +40 · F_BLACKLISTED_IP +45',
          'LOW 0–30 → دخول مباشر · MEDIUM 31–69 → موافقة عبر جهاز آخر · HIGH 70–100 → إغلاق فوري',
          'كل قرار يُسجَّل في سجل أحداث تفصيلي ويُبث حيًّا']),
        ('سيناريوهات SRS', 'ثلاثة مستويات صارمة',
         ['S1: كلمة مرور فقط في مستوى LOW',
          'S2: كلمة مرور + رمز OTP (RFC 6238)',
          'S3: OTP + بريد + RBAC — وغرفة العمليات للمشرف فقط']),
        ('الجهاز الموثوق', 'من «بريد يصل» إلى «جهاز موثوق»',
         ['تسجيل + بريد تحقق حقيقي (Ethereal)',
          'النقر على رابط التحقق يختم المتصفح كجهاز موثوق (كوكي مشفّر سنة)',
          'إلغاء الأجهزة من مركز الأمان']),
        ('v2 · البوابة المدرسية', 'RBAC صارم عبر 3 أدوار',
         ['8 وحدات × 3 أدوار (مقررات/درجات/تكليفات/حضور/قوائم صفية/دليل مستخدمين)',
          'الطالب: مُحرَم من القوائم والدليل والمصفوفة (403)',
          'المشرف: كل الوحدات + مصفوفة صلاحيات مُعروضة']),
        ('v2 · الأمان', 'استرداد الحساب + إعادة ضبط MFA',
         ['request → reset → validate — رمز تحقق 6 خانات',
          'تدوير TOTP + كلمة مرور + 10 رموز استرداد أحادية الاستخدام',
          'كل خطوة مسجّلةً في سجل الأحداث']),
        ('v2 · التحقيق والأداء', 'Forensics + Benchmark',
         ['إعادة بناء خط زمني للأحداث حسب المستخدم/IP/الجهاز/النتيجة',
          'قضايا تلتقط الأدلة تلقائيًا مع تصدير Markdown جاهز للأرشفة',
          'مقارنة سيناريوهات المصادقة بزمن حقيقي elapsed_ms']),
        ('لوحة SOC', 'غرفة عمليات حيّة لحظيًا',
         ['Overview · Audit · Sessions · Trusted Devices · Factors · Blacklist · Attack Sim',
          'بث SSE: أحداث الدخول والتنبيهات تصل فورًا',
          'الهجمات المحاكية A (قوة غاشمة) · B (سفر مستحيل) · C (حقن بيانات مسروقة)']),
        ('النتائج', 'اختبار شامل — كل المراحل خضراء',
         ['140 فحصًا آليًا على قاعدة نظيفة',
          'e2e 77 يشمل بوابة/استرداد/تحقيق/أداء + اختبار بقاء البيانات بعد إعادة التشغيل',
          'dem مع demo.mp4 يغطي كل ميزة أثناء العمل']),
        ('آفاق مستقبلية', 'ماذا لو طُبّق في بيئة إنتاجية؟',
         ['عوامل إضافية: بصمة الوجه/الجهاز وخطر الموقع الجغرافي الحقيقي',
          'تعلم آلي لعادات الدخول لكل مستخدم',
          'عزل تلقائي وإنذار منصات المراقبة ومشاركة التهديدات']),
        ('شكرًا', 'AuthShield 360',
         ['شغّل: npm start ثم localhost:4000',
          'التسليمات: dist/AuthShield360-v2.zip · docs/ · demo.mp4']),
    ]
    build_pptx(slides, ROOT / 'docs' / 'technical' / 'Presentation_Deck.pptx')

    # Deck PDF — print-quality standalone pages (1 slide = 1 landscape page)
    logo_b64 = base64.b64encode((ROOT / 'frontend' / 'assets' / 'logo.svg').read_bytes()).decode()
    deck_html = ['<!doctype html><html dir="rtl"><head><meta charset="utf-8"><style>'
                 '@page{size:13.333in 7.5in;margin:0}'
                 'html,body{margin:0;padding:0}'
                 '.pg{width:13.333in;height:7.5in;box-sizing:border-box;page-break-after:always;'
                 'padding:0.62in 0.8in 0.5in;background:#ffffff;color:#152a3c;font-family:"Segoe UI",Tahoma;'
                 'display:flex;flex-direction:column;justify-content:center;border-top:14px solid #0f766e}'
                 '.pg:last-child{page-break-after:auto}'
                 '.hd{position:absolute;top:0.14in;right:0.8in;display:flex;gap:9px;align-items:center;font-size:9pt;color:#4c6377;font-weight:700}\n'
                 '.hd img{width:22px;height:22px}\n'
                 '.kick{color:#1d4ed8;font-size:20pt;margin:0 0 10px;letter-spacing:1px}',
                 '.tt{color:#0f766e;font-size:40pt;font-weight:700;margin:0 0 26px}'
                 'ul{list-style:none;margin:0;padding:0}li{font-size:20pt;margin:14px 0;padding-inline-start:0.3in;color:#16283b}'
                 'li::before{content:"●  ";color:#0d7a45}'
                 '.bar{height:10px;background:linear-gradient(90deg,#0f766e,#1d4ed8);margin-top:auto;width:100%}'
                 '</style></head><body>']
    for kicker, title, items in slides:
        deck_html.append(f'<div class="pg"><div class="hd"><img src="data:image/svg+xml;base64,{logo_b64}"/>'
                         f'<span>Cornell Deep &middot; Identity Protection Platform</span></div>'
                         f'<div class="kick">{_html.escape(kicker)}</div>'
                         f'<div class="tt">{_html.escape(title).replace(chr(10), "<br/>")}</div><ul>' +
                         ''.join(f'<li>{_html.escape(it)}</li>' for it in items) +
                         '<div class="bar"></div></div>')
    deck_html.append('</body></html>')
    deck = ROOT / 'docs' / 'technical' / 'Presentation_Deck.pdf'
    render_pdf('\n'.join(deck_html), deck)

if __name__ == '__main__':
    main()
    print('done.')
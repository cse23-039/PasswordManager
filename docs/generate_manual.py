#!/usr/bin/env python3
"""
Generate FULL_MANUAL.pdf for Password Manager.
Dark, Kinetiq-inspired design: navy backgrounds, teal accents, card grids.

Usage:
    python docs/generate_manual.py
"""

import os
import sys
from fpdf import FPDF
from fpdf.enums import XPos, YPos

# ── Paths ────────────────────────────────────────────────────────────────────
SCRIPT_DIR  = os.path.dirname(os.path.abspath(__file__))
LOGO_PATH   = os.path.join(SCRIPT_DIR, '..', 'logo.png')
OUT_PATH    = os.path.join(SCRIPT_DIR, 'FULL_MANUAL.pdf')
FONTS_DIR   = r'C:\Windows\Fonts'

# ── Color palette ─────────────────────────────────────────────────────────────
BG       = (13,  17,  23)    # #0d1117  page background
CARD     = (22,  27,  34)    # #161b22  card surface
BAND     = (27,  42,  59)    # #1b2a3b  header bands / cover
TEAL     = (0,  212, 170)    # #00d4aa  primary accent
BLUE     = (47, 129, 247)    # #2f81f7  secondary accent
WHITE    = (230, 237, 243)   # #e6edf3  body text
MUTED    = (139, 148, 158)   # #8b949e  muted / secondary text
RED      = (248,  81,  73)   # #f85149  danger / admin badge
AMBER    = (210, 153,  34)   # #d29922  warning / security officer badge
GREEN    = (63,  185, 110)   # #3fb96e  success / active badge

# ── Layout constants ──────────────────────────────────────────────────────────
PAGE_W   = 210
PAGE_H   = 297
MARGIN   = 14
CW       = PAGE_W - 2 * MARGIN   # content width = 182 mm

# ─────────────────────────────────────────────────────────────────────────────
class ManualPDF(FPDF):

    def __init__(self):
        super().__init__('P', 'mm', 'A4')
        self.current_chapter = ''
        self.set_auto_page_break(True, margin=22)
        self.set_margins(MARGIN, 18, MARGIN)
        # Load Unicode TTF fonts from Windows (Segoe UI has broad Unicode coverage)
        fd = FONTS_DIR
        self.add_font('Arial',      '',  os.path.join(fd, 'segoeui.ttf'))
        self.add_font('Arial',      'B', os.path.join(fd, 'segoeuib.ttf'))
        self.add_font('Arial',      'I', os.path.join(fd, 'segoeuii.ttf'))
        self.add_font('CourierNew', '',  os.path.join(fd, 'cour.ttf'))
        self.add_font('CourierNew', 'B', os.path.join(fd, 'courbd.ttf'))

    # ── Page header ───────────────────────────────────────────────────────────
    def header(self):
        if self.page_no() == 1:
            return
        # Paint the full dark background first — this is what prevents white
        # pages whenever FPDF auto-triggers a page break mid-content.
        self.set_fill_color(*BG)
        self.rect(0, 0, PAGE_W, PAGE_H, 'F')
        # Header band on top
        self.set_fill_color(*BAND)
        self.rect(0, 0, PAGE_W, 14, 'F')
        logo_ok = os.path.exists(LOGO_PATH)
        lx = MARGIN
        if logo_ok:
            self.image(LOGO_PATH, lx, 3, 7)
            lx += 9
        self.set_xy(lx, 4.5)
        self.set_font('Arial', 'B', 7.5)
        self.set_text_color(*WHITE)
        self.cell(55, 5, 'Password Manager', new_x=XPos.RIGHT, new_y=YPos.TOP)
        self.set_xy(PAGE_W - MARGIN - 85, 4.5)
        self.set_font('Arial', '', 6.5)
        self.set_text_color(*MUTED)
        self.cell(85, 5, self.current_chapter, align='R',
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    # ── Page footer ───────────────────────────────────────────────────────────
    def footer(self):
        if self.page_no() == 1:
            return
        self.set_y(-13)
        self.set_fill_color(*BAND)
        self.rect(0, PAGE_H - 13, PAGE_W, 13, 'F')
        self.set_xy(MARGIN, PAGE_H - 9)
        self.set_font('Arial', '', 6)
        self.set_text_color(*MUTED)
        self.cell(CW - 14, 5,
                  'Password Manager v1.0.0  ·  © 2026 Kagiso Setwaba. All rights reserved.',
                  align='C', new_x=XPos.RIGHT, new_y=YPos.TOP)
        self.set_font('Arial', 'B', 7)
        self.set_text_color(*TEAL)
        self.cell(14, 5, str(self.page_no()), align='R')

    # ── Helpers ───────────────────────────────────────────────────────────────

    def bg(self):
        self.set_fill_color(*BG)
        self.rect(0, 0, PAGE_W, PAGE_H, 'F')

    def new_content_page(self, chapter=''):
        # Do NOT call self.bg() here — header() now paints the dark background
        # on every non-cover page. Calling bg() after add_page() would wipe
        # the header band that header() just drew.
        self.add_page()
        if chapter:
            self.current_chapter = chapter

    def _text_height(self, text, chars_per_line=60, line_h=5.0):
        """Conservative multi_cell height estimate used for pre-draw box sizing."""
        lines = max(1, len(text) // chars_per_line + text.count('\n') + 1)
        return lines * line_h

    def section_label(self, text):
        if self.get_y() > PAGE_H - 40:
            self.new_content_page()
        self.set_font('Arial', 'B', 6.5)
        self.set_text_color(*TEAL)
        self.cell(CW, 4, text.upper(), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(0.5)

    def h1(self, text):
        self.set_font('Arial', 'B', 20)
        self.set_text_color(*WHITE)
        self.multi_cell(CW, 10, text, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(2)

    def h2(self, text):
        self.ln(3)
        if self.get_y() > PAGE_H - 32:
            self.new_content_page()
        self.set_font('Arial', 'B', 13)
        self.set_text_color(*WHITE)
        self.multi_cell(CW, 7, text, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(1)

    def h3(self, text):
        self.ln(2)
        if self.get_y() > PAGE_H - 28:
            self.new_content_page()
        self.set_font('Arial', 'B', 10)
        self.set_text_color(*TEAL)
        self.multi_cell(CW, 5.5, text, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    def body(self, text):
        self.set_font('Arial', '', 9.5)
        self.set_text_color(*WHITE)
        self.multi_cell(CW, 5, text, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(1)

    def muted(self, text):
        self.set_font('Arial', '', 8.5)
        self.set_text_color(*MUTED)
        self.multi_cell(CW, 5, text, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(1)

    def bullets(self, items, indent=5):
        for item in items:
            # Estimate height and break before drawing so the arrow and text
            # always land on the same page.
            est_h = self._text_height(item, chars_per_line=55, line_h=5) + 2
            if self.get_y() + est_h > PAGE_H - 22:
                self.new_content_page()
            self.set_x(MARGIN + indent - 3)
            self.set_font('Arial', 'B', 9)
            self.set_text_color(*TEAL)
            self.cell(4, 5, '→', new_x=XPos.RIGHT, new_y=YPos.TOP)
            self.set_font('Arial', '', 9.5)
            self.set_text_color(*WHITE)
            self.multi_cell(CW - indent - 1, 5, item, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.ln(1)

    def code_block(self, text):
        lines = text.split('\n')
        h = len(lines) * 4.8 + 6
        y = self.get_y()
        if y + h > PAGE_H - 22:
            self.new_content_page()
            y = self.get_y()
        self.set_fill_color(*CARD)
        self.rect(MARGIN, y, CW, h, 'F')
        self.set_fill_color(*TEAL)
        self.rect(MARGIN, y, 1.5, h, 'F')
        self.set_xy(MARGIN + 4, y + 3)
        self.set_font('CourierNew', '', 7.5)
        self.set_text_color(*TEAL)
        for line in lines:
            self.set_x(MARGIN + 4)
            self.cell(CW - 6, 4.8, line, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_y(y + h + 4)

    def callout(self, text, danger=False):
        accent = RED if danger else BLUE
        # 58 chars/line is conservative for 9pt italic in ~175 mm width
        h = self._text_height(text, chars_per_line=58, line_h=5) + 10
        y = self.get_y()
        if y + h > PAGE_H - 22:
            self.new_content_page()
            y = self.get_y()
        self.set_fill_color(*CARD)
        self.rect(MARGIN, y, CW, h, 'F')
        self.set_fill_color(*accent)
        self.rect(MARGIN, y, 2, h, 'F')
        self.set_xy(MARGIN + 5, y + 4)
        self.set_font('Arial', 'I', 9)
        self.set_text_color(*WHITE)
        self.multi_cell(CW - 7, 5, text, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_y(y + h + 4)

    def stat_strip(self, stats):
        """stats = list of (value_str, label_str)."""
        n = len(stats)
        cw = CW / n
        y = self.get_y()
        if y + 28 > PAGE_H - 22:
            self.new_content_page()
            y = self.get_y()
        self.set_fill_color(*CARD)
        self.rect(MARGIN, y, CW, 24, 'F')
        self.set_fill_color(*TEAL)
        self.rect(MARGIN, y, CW, 1.5, 'F')
        for i, (val, lbl) in enumerate(stats):
            x = MARGIN + i * cw
            self.set_xy(x, y + 4)
            self.set_font('Arial', 'B', 13)
            self.set_text_color(*TEAL)
            self.cell(cw, 8, val, align='C', new_x=XPos.RIGHT, new_y=YPos.TOP)
            self.set_xy(x, y + 13)
            self.set_font('Arial', '', 6)
            self.set_text_color(*MUTED)
            self.cell(cw, 5, lbl.upper(), align='C', new_x=XPos.RIGHT, new_y=YPos.TOP)
            if i < n - 1:
                self.set_draw_color(*BG)
                self.line(x + cw, y + 5, x + cw, y + 19)
        self.set_y(y + 28)

    def card(self, title, body_text, label='', accent=None):
        if accent is None:
            accent = TEAL
        # 42 chars/line for 10pt bold title, 50 chars/line for 9pt body
        title_h = self._text_height(title, chars_per_line=42, line_h=6)
        body_h  = self._text_height(body_text, chars_per_line=50, line_h=4.8)
        h = (5 if label else 0) + title_h + body_h + 12
        y = self.get_y()
        if y + h > PAGE_H - 22:
            self.new_content_page()
            y = self.get_y()
        self.set_fill_color(*CARD)
        self.rect(MARGIN, y, CW, h, 'F')
        self.set_fill_color(*accent)
        self.rect(MARGIN, y, 2, h, 'F')
        off = 4
        if label:
            self.set_xy(MARGIN + 5, y + off)
            self.set_font('Arial', 'B', 6.5)
            self.set_text_color(*accent)
            self.cell(CW - 7, 4, label.upper(), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            off += 5
        self.set_xy(MARGIN + 5, y + off)
        self.set_font('Arial', 'B', 10)
        self.set_text_color(*WHITE)
        self.multi_cell(CW - 7, 6, title, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_x(MARGIN + 5)
        self.set_font('Arial', '', 9)
        self.set_text_color(*WHITE)
        self.multi_cell(CW - 7, 4.8, body_text, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_y(y + h + 4)

    def card_grid(self, cards):
        """2-column grid: cards = list of (title, body, label)."""
        col_w = (CW - 4) / 2

        def _est(c):
            if c is None:
                return 0
            title, body_text, label = c
            # Conservative: 28 chars/line for title at 10pt, 36 for body at 8.5pt
            th = self._text_height(title, chars_per_line=28, line_h=5.5)
            bh = self._text_height(body_text, chars_per_line=36, line_h=4.5)
            return (5 if label else 0) + th + bh + 14

        for i in range(0, len(cards), 2):
            left  = cards[i]
            right = cards[i + 1] if i + 1 < len(cards) else None
            h = max(_est(left), _est(right), 32)
            y = self.get_y()
            if y + h > PAGE_H - 22:
                self.new_content_page()
                y = self.get_y()
            for ci, cd in enumerate([left, right]):
                if cd is None:
                    continue
                title, body_text, label = cd
                x   = MARGIN + ci * (col_w + 4)
                acc = TEAL if ci == 0 else BLUE
                self.set_fill_color(*CARD)
                self.rect(x, y, col_w, h, 'F')
                self.set_fill_color(*acc)
                self.rect(x, y, col_w, 1.5, 'F')
                off = 4
                if label:
                    self.set_xy(x + 4, y + off)
                    self.set_font('Arial', 'B', 6.5)
                    self.set_text_color(*acc)
                    self.cell(col_w - 5, 4, label.upper(),
                              new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                    off += 5
                self.set_xy(x + 4, y + off)
                self.set_font('Arial', 'B', 10)
                self.set_text_color(*WHITE)
                self.multi_cell(col_w - 6, 5.5, title,
                                new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                self.set_x(x + 4)
                self.set_font('Arial', '', 8.5)
                self.set_text_color(*WHITE)
                self.multi_cell(col_w - 6, 4.5, body_text,
                                new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            self.set_y(y + h + 4)

    def numbered_step(self, num, title, desc='', label=''):
        desc_h = self._text_height(desc, chars_per_line=58, line_h=5) if desc else 0
        h_needed = (4 if label else 0) + 8 + desc_h + 10
        y = self.get_y()
        if y + h_needed > PAGE_H - 22:
            self.new_content_page()
            y = self.get_y()
        # Circle
        cx, cy = MARGIN + 5, y + 5
        self.set_fill_color(*TEAL)
        self.ellipse(cx - 5, cy - 4, 10, 10, 'F')
        self.set_xy(cx - 5, cy - 3.5)
        self.set_font('Arial', 'B', 8)
        self.set_text_color(*BG)
        self.cell(10, 7, str(num), align='C', new_x=XPos.RIGHT, new_y=YPos.TOP)
        # Label
        tx = MARGIN + 14
        ty = y
        if label:
            self.set_xy(tx, ty)
            self.set_font('Arial', 'B', 6)
            self.set_text_color(*TEAL)
            self.cell(CW - 14, 4, label.upper(), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            ty += 4
        # Title
        self.set_xy(tx, ty)
        self.set_font('Arial', 'B', 11)
        self.set_text_color(*WHITE)
        self.multi_cell(CW - 14, 6, title, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        # Desc
        if desc:
            self.set_x(tx)
            self.set_font('Arial', '', 9)
            self.set_text_color(*WHITE)
            self.multi_cell(CW - 14, 5, desc, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        # Rule
        self.set_draw_color(*CARD)
        self.line(MARGIN, self.get_y() + 2, PAGE_W - MARGIN, self.get_y() + 2)
        self.ln(5)

    def dark_table(self, headers, rows, col_widths=None):
        if col_widths is None:
            col_widths = [CW / len(headers)] * len(headers)
        ROW_H = 6
        HDR_H = 7

        def _draw_header(y):
            self.set_fill_color(*BAND)
            self.set_font('Arial', 'B', 7.5)
            self.set_text_color(*TEAL)
            for i, hdr in enumerate(headers):
                self.set_xy(MARGIN + sum(col_widths[:i]), y)
                self.cell(col_widths[i], HDR_H, '  ' + hdr, fill=True,
                          new_x=XPos.RIGHT, new_y=YPos.TOP)
            return y + HDR_H

        y = self.get_y()
        if y + HDR_H + ROW_H > PAGE_H - 22:
            self.new_content_page()
            y = self.get_y()
        y = _draw_header(y)

        self.set_font('Arial', '', 8)
        for ri, row in enumerate(rows):
            # Mid-table page break: redraw header on continuation page
            if y + ROW_H > PAGE_H - 22:
                self.new_content_page()
                y = self.get_y()
                y = _draw_header(y)
                self.set_font('Arial', '', 8)
            fc = CARD if ri % 2 == 0 else BG
            self.set_fill_color(*fc)
            for ci, val in enumerate(row):
                vstr = str(val)
                self.set_xy(MARGIN + sum(col_widths[:ci]), y)
                if vstr in ('Administrator', 'Admin'):
                    self.set_text_color(*RED)
                elif vstr == 'Security Officer':
                    self.set_text_color(*AMBER)
                elif vstr in ('Active', 'PASS', 'Yes'):
                    self.set_text_color(*TEAL)
                elif vstr in ('Revoked', 'FAIL', 'No'):
                    self.set_text_color(*RED)
                elif vstr in ('WARN', '-', 'N/A'):
                    self.set_text_color(*MUTED)
                else:
                    self.set_text_color(*WHITE)
                self.cell(col_widths[ci], ROW_H, '  ' + vstr, fill=True,
                          new_x=XPos.RIGHT, new_y=YPos.TOP)
            y += ROW_H
        self.set_y(y + 4)

    def comparison_table(self, left_header, right_header, rows):
        cw2 = CW / 2
        row_h = 8

        def _draw_comp_header(y):
            self.set_fill_color(*BAND)
            self.set_font('Arial', 'B', 8.5)
            self.set_text_color(*MUTED)
            self.set_xy(MARGIN, y)
            self.cell(cw2, row_h, '  ' + left_header, fill=True,
                      new_x=XPos.RIGHT, new_y=YPos.TOP)
            self.set_text_color(*TEAL)
            self.cell(cw2, row_h, '  ' + right_header, fill=True,
                      new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            return y + row_h

        y = self.get_y()
        if y + row_h * 3 > PAGE_H - 22:
            self.new_content_page()
            y = self.get_y()
        y = _draw_comp_header(y)

        for ri, (left, right) in enumerate(rows):
            if y + row_h > PAGE_H - 22:
                self.new_content_page()
                y = self.get_y()
                y = _draw_comp_header(y)
            fc = CARD if ri % 2 == 0 else BG
            self.set_fill_color(*fc)
            self.set_font('Arial', '', 8.5)
            self.set_text_color(*MUTED)
            self.set_xy(MARGIN, y)
            self.cell(cw2, row_h, '  ' + left[:54], fill=True,
                      new_x=XPos.RIGHT, new_y=YPos.TOP)
            self.set_fill_color(*CARD)
            self.set_text_color(*WHITE)
            self.cell(cw2, row_h, '  ' + right[:60], fill=True,
                      new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            y += row_h
        self.set_y(y + 4)

    def chapter_opener(self, num, title, subtitle=''):
        self.add_page()
        # header() already painted the dark BG — do NOT call self.bg() here.
        self.current_chapter = f'Chapter {num}  —  {title}'
        # Opener band (taller than the normal 14 mm header band)
        self.set_fill_color(*BAND)
        self.rect(0, 0, PAGE_W, 62, 'F')
        # Teal left edge stripe
        self.set_fill_color(*TEAL)
        self.rect(0, 0, 3, 62, 'F')
        # Chapter tag
        self.set_xy(MARGIN, 18)
        self.set_font('Arial', 'B', 8)
        self.set_text_color(*TEAL)
        self.cell(CW, 5, f'CHAPTER {num}', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        # Title
        self.set_xy(MARGIN, 25)
        self.set_font('Arial', 'B', 22)
        self.set_text_color(*WHITE)
        self.multi_cell(CW, 11, title, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        # Subtitle
        if subtitle:
            self.set_x(MARGIN)
            self.set_font('Arial', '', 10)
            self.set_text_color(*MUTED)
            self.multi_cell(CW, 5.5, subtitle, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        # Teal underline bar + blue dot accent
        self.set_fill_color(*TEAL)
        self.rect(MARGIN, 59, 40, 1.5, 'F')
        self.set_fill_color(*BLUE)
        self.rect(MARGIN + 44, 59, 10, 1.5, 'F')
        # Start content below the band, adapting if a long subtitle pushed past y=72
        self.set_y(max(80, self.get_y() + 10))


# ═════════════════════════════════════════════════════════════════════════════
# Content builders
# ═════════════════════════════════════════════════════════════════════════════

def build_cover(pdf):
    pdf.add_page()
    # Full dark cover
    pdf.set_fill_color(*BAND)
    pdf.rect(0, 0, PAGE_W, PAGE_H, 'F')
    # Subtle gradient layer
    pdf.set_fill_color(*BG)
    pdf.rect(0, PAGE_H // 2, PAGE_W, PAGE_H // 2, 'F')

    # Logo
    logo_ok = os.path.exists(LOGO_PATH)
    logo_y = 52
    if logo_ok:
        pdf.image(LOGO_PATH, (PAGE_W - 28) / 2, logo_y, 28)
        logo_y += 35
    else:
        logo_y = 75

    # Lock icon placeholder if no logo
    if not logo_ok:
        pdf.set_fill_color(*TEAL)
        pdf.ellipse((PAGE_W - 18) / 2, logo_y - 18, 18, 18, 'F')
        pdf.set_xy(0, logo_y - 14)
        pdf.set_font('Arial', 'B', 14)
        pdf.set_text_color(*BG)
        pdf.cell(PAGE_W, 10, 'PM', align='C', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        logo_y = 75

    # Title
    pdf.set_xy(0, logo_y)
    pdf.set_font('Arial', 'B', 32)
    pdf.set_text_color(*WHITE)
    pdf.cell(PAGE_W, 16, 'Password Manager', align='C',
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    # Subtitle teal
    pdf.set_font('Arial', 'B', 13)
    pdf.set_text_color(*TEAL)
    pdf.cell(PAGE_W, 8, 'Secure Enterprise Vault', align='C',
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    # Tagline
    pdf.ln(3)
    pdf.set_font('Arial', '', 10)
    pdf.set_text_color(*MUTED)
    pdf.cell(PAGE_W, 6,
             'Every secret encrypted. Every access audited. Zero plaintext stored.',
             align='C', new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    # Divider
    pdf.ln(6)
    pdf.set_fill_color(*TEAL)
    pdf.rect((PAGE_W - 30) / 2, pdf.get_y(), 30, 1, 'F')
    pdf.ln(8)

    # Stat strip
    stats = [
        ('AES-256', 'Encryption'),
        ('ARGON2ID', 'Key Derivation'),
        ('TOTP MFA', 'Auth Factor'),
        ('0', 'Plaintext Stored'),
    ]
    sw = 155
    sx = (PAGE_W - sw) / 2
    sy = pdf.get_y()
    pdf.set_fill_color(*CARD)
    pdf.rect(sx, sy, sw, 26, 'F')
    pdf.set_fill_color(*TEAL)
    pdf.rect(sx, sy, sw, 1.5, 'F')
    cw = sw / len(stats)
    for i, (val, lbl) in enumerate(stats):
        x = sx + i * cw
        pdf.set_xy(x, sy + 4)
        pdf.set_font('Arial', 'B', 11)
        pdf.set_text_color(*TEAL)
        pdf.cell(cw, 7, val, align='C', new_x=XPos.RIGHT, new_y=YPos.TOP)
        pdf.set_xy(x, sy + 13)
        pdf.set_font('Arial', '', 5.5)
        pdf.set_text_color(*MUTED)
        pdf.cell(cw, 5, lbl.upper(), align='C', new_x=XPos.RIGHT, new_y=YPos.TOP)
        if i < len(stats) - 1:
            pdf.set_draw_color(*BG)
            pdf.line(x + cw, sy + 5, x + cw, sy + 21)

    # Version
    pdf.set_xy(0, PAGE_H - 48)
    pdf.set_font('Arial', 'B', 9)
    pdf.set_text_color(*WHITE)
    pdf.cell(PAGE_W, 6, 'Full Application Manual  ·  Version 1.0.0  ·  March 2026',
             align='C', new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    # Author
    pdf.set_font('Arial', '', 8)
    pdf.set_text_color(*MUTED)
    pdf.cell(PAGE_W, 5, 'Authored by Kagiso Setwaba', align='C',
             new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    pdf.ln(2)
    pdf.set_font('Arial', '', 7)
    pdf.cell(PAGE_W, 5,
             'LinkedIn: linkedin.com/in/kagiso-setwaba  ·  GitHub: github.com/KSetwaba',
             align='C', new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    # Footer copyright
    pdf.set_xy(0, PAGE_H - 16)
    pdf.set_font('Arial', '', 6.5)
    pdf.set_text_color(*MUTED)
    pdf.cell(PAGE_W, 5,
             '© 2026 Kagiso Setwaba. All rights reserved.  '
             'Password Manager is a secure, locally-hosted credential vault.',
             align='C')


def build_toc(pdf):
    pdf.new_content_page('Table of Contents')
    pdf.section_label('Navigation')
    pdf.h1('Table of Contents')
    pdf.ln(2)

    chapters = [
        ('1', 'Overview', 'Platform capabilities and security architecture'),
        ('2', 'Quick Start', 'Install and run in under 5 minutes'),
        ('3', 'Setup & Configuration', 'System requirements, installer, env vars'),
        ('4', 'User Manual', 'Login, secrets, settings, admin dashboard'),
        ('5', 'Deployment Guide', 'Desktop, Docker, production hardening'),
        ('6', 'Architecture', 'Package structure, vault format, crypto'),
        ('7', 'Password Management', 'Secrets, history, generator, sharing'),
        ('8', 'Security', 'Requirements, testing, threat model'),
        ('9', 'File Manifest & Reference', 'Source map, permissions, env vars'),
    ]

    col_w = (CW - 4) / 2
    for i in range(0, len(chapters), 2):
        y = pdf.get_y()
        if y > PAGE_H - 35:
            pdf.new_content_page('Table of Contents')
            y = pdf.get_y()
        for ci in range(2):
            idx = i + ci
            if idx >= len(chapters):
                break
            num, title, desc = chapters[idx]
            x = MARGIN + ci * (col_w + 4)
            h = 22
            pdf.set_fill_color(*CARD)
            pdf.rect(x, y, col_w, h, 'F')
            # Teal number circle
            pdf.set_fill_color(*TEAL)
            pdf.ellipse(x + 4, y + 3, 9, 9, 'F')
            pdf.set_xy(x + 4, y + 3.5)
            pdf.set_font('Arial', 'B', 7)
            pdf.set_text_color(*BG)
            pdf.cell(9, 7, num, align='C', new_x=XPos.RIGHT, new_y=YPos.TOP)
            # Title
            pdf.set_xy(x + 15, y + 4)
            pdf.set_font('Arial', 'B', 9.5)
            pdf.set_text_color(*WHITE)
            pdf.cell(col_w - 17, 6, title, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            # Desc
            pdf.set_xy(x + 15, y + 11)
            pdf.set_font('Arial', '', 7.5)
            pdf.set_text_color(*MUTED)
            pdf.multi_cell(col_w - 17, 4.5, desc, new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_y(y + 26)


def build_ch1(pdf):
    pdf.chapter_opener('1', 'Overview',
                       'What Password Manager is, why it exists, and how it stays secure.')

    pdf.section_label('The Problem')
    pdf.h2('What every other password manager gets wrong.')
    pdf.body(
        'Most credential tools store your passwords behind a single master password, '
        'run on someone else\'s cloud, and provide no meaningful audit trail. '
        'One breach exposes everything. Password Manager was built differently: '
        'local-first, zero-cloud, with military-grade encryption on every individual secret.'
    )
    pdf.ln(2)

    pdf.card_grid([
        ('Plaintext in the cloud',
         'Cloud-hosted vaults rely on the provider\'s security. One upstream breach '
         'or insider threat exposes every user\'s credentials simultaneously.',
         'CONVENTIONAL APPS'),
        ('AES-256-GCM per entry',
         'Every secret is encrypted individually with its own derived key. Compromising '
         'one entry reveals nothing about any other. Zero plaintext ever leaves your machine.',
         'PASSWORD MANAGER'),
        ('No access control',
         'Single-user tools offer no concept of roles. Any logged-in user can read, '
         'modify, or delete every credential in the vault.',
         'CONVENTIONAL APPS'),
        ('RBAC with 17 permissions',
         'Four roles — Administrator, Security Officer, Standard User, Read-Only — '
         'each with granular per-action permissions enforced at the API layer.',
         'PASSWORD MANAGER'),
        ('No audit trail',
         'You have no way of knowing who accessed a secret, when, or from where. '
         'Forensic investigation after a breach is impossible.',
         'CONVENTIONAL APPS'),
        ('HMAC-chained audit log',
         'Every action is written to a tamper-evident log. Each entry includes a '
         'SHA-256 chain link; any deletion or modification is immediately detectable.',
         'PASSWORD MANAGER'),
        ('Single factor auth',
         'Username + password only. No second factor, no lockout after repeated failures, '
         'no brute-force protection.',
         'CONVENTIONAL APPS'),
        ('TOTP MFA + lockout',
         'RFC 6238 time-based one-time passwords with ±1 time-step tolerance. '
         'Accounts lock after 5 failed attempts for 15 minutes (configurable).',
         'PASSWORD MANAGER'),
    ])

    pdf.ln(2)
    pdf.section_label('Platform at a glance')
    pdf.stat_strip([
        ('AES-256', 'Encryption'),
        ('4 ROLES', 'Access Control'),
        ('17', 'Granular Permissions'),
        ('365 DAYS', 'Audit Retention'),
    ])

    pdf.section_label('Architecture summary')
    pdf.h2('Local-first. Zero-trust. Fully audited.')
    pdf.body(
        'Password Manager is a desktop application built with Go and the Fyne UI toolkit. '
        'The vault is a single encrypted file (vault.pwm) stored on your local machine. '
        'No data is transmitted to any remote server. The application\'s core engine '
        'separates concerns cleanly: the crypto layer handles all key derivation and '
        'encryption, the vault layer manages the file format and persistence, '
        'the auth layer enforces RBAC and MFA, and the audit layer maintains an '
        'immutable, integrity-verified event log.'
    )

    pdf.card_grid([
        ('Crypto Layer',
         'Argon2id key derivation (t=3, m=64 MB, p=4). AES-256-GCM for all encryption. '
         'PBKDF2 for legacy compatibility. 90-day automatic key rotation.',
         'CORE ENGINE'),
        ('Vault Layer',
         'Atomic file writes with fsync. Per-entry encrypted blobs. '
         'Timestamped backup snapshots (.pwm.bak). Optional encrypted key storage.',
         'PERSISTENCE'),
        ('RBAC + MFA',
         '17-permission grid across 4 roles. TOTP RFC 6238. Session tokens '
         'with 15-min idle timeout and 8-hour hard ceiling.',
         'ACCESS CONTROL'),
        ('Audit Engine',
         'HMAC-SHA256 chained log. 24 auditable action constants. '
         'JSON / CSV / CEF / Syslog export. 365-day retention.',
         'COMPLIANCE'),
    ])


def build_ch2(pdf):
    pdf.chapter_opener('2', 'Quick Start',
                       'From download to first secret in under 5 minutes.')

    pdf.section_label('Windows — Inno Setup Installer')
    pdf.h2('Get running in 6 steps.')
    pdf.body(
        'Password Manager ships as a signed Inno Setup installer for Windows. '
        'No manual PATH configuration, no dependencies to install manually. '
        'The installer handles everything.'
    )
    pdf.ln(2)

    pdf.numbered_step(1, 'Run the installer',
                      'Double-click PasswordManager-Setup-1.0.0.exe and follow the wizard. '
                      'Default install path: C:\\Program Files\\Password Manager\\',
                      'DOWNLOAD & INSTALL')
    pdf.numbered_step(2, 'Launch from Start Menu',
                      'Open Start → Password Manager, or use the optional desktop shortcut '
                      'created during installation.',
                      'LAUNCH')
    pdf.numbered_step(3, 'Create your vault',
                      'On first launch you will be prompted to choose a vault key (minimum 8 '
                      'characters). This key encrypts the vault file. Store it safely — '
                      'it cannot be recovered.',
                      'VAULT SETUP')
    pdf.numbered_step(4, 'Register the first admin account',
                      'Enter a username, a strong password (min 12 chars, upper/lower/digit/special), '
                      'and confirm. The first registered account is automatically granted the '
                      'Administrator role.',
                      'REGISTRATION')
    pdf.numbered_step(5, 'Enable TOTP MFA',
                      'Scan the displayed QR code with an authenticator app (Google Authenticator, '
                      'Authy, etc.) and verify with a 6-digit code to activate two-factor authentication.',
                      'MFA SETUP')
    pdf.numbered_step(6, 'Add your first secret',
                      'Click Add Secret in the sidebar, fill in the name, username, password, URL, '
                      'category, and optional tags. Click Save. Your secret is encrypted immediately.',
                      'FIRST SECRET')

    pdf.callout(
        'The vault file is stored at %APPDATA%\\PasswordManager\\vault.pwm on Windows '
        'and ~/.config/PasswordManager/vault.pwm on Linux/macOS. '
        'Back it up regularly using the Export Vault Backup feature in the Admin Dashboard.'
    )

    pdf.section_label('Linux & macOS')
    pdf.h2('Build from source with Make.')
    pdf.code_block(
        '# Clone and build\n'
        'git clone https://github.com/KSetwaba/PasswordManager.git\n'
        'cd PasswordManager\n'
        'make run\n\n'
        '# Or build binary only\n'
        'make build\n'
        './bin/password-manager'
    )
    pdf.body(
        'Requires Go 1.24+ and the Fyne dependencies for your platform. '
        'On Debian/Ubuntu: sudo apt-get install libgl1-mesa-dev xorg-dev'
    )


def build_ch3(pdf):
    pdf.chapter_opener('3', 'Setup & Configuration',
                       'System requirements, environment variables, and first-run walkthrough.')

    pdf.section_label('System Requirements')
    pdf.h2('Platform prerequisites.')
    pdf.dark_table(
        ['Component', 'Minimum', 'Recommended'],
        [
            ['OS', 'Windows 10 / Ubuntu 20.04 / macOS 12', 'Windows 11 / Ubuntu 22.04'],
            ['CPU', 'Dual-core 2 GHz', 'Quad-core 3 GHz'],
            ['RAM', '512 MB free', '1 GB free'],
            ['Disk', '100 MB', '500 MB (for vault growth)'],
            ['Go (build only)', '1.21+', '1.24+'],
            ['Fyne deps (Linux)', 'libgl1-mesa-dev, xorg-dev', 'Same'],
        ],
        col_widths=[42, 78, 62]
    )

    pdf.section_label('Installation Options')
    pdf.h2('Three ways to deploy.')
    pdf.card_grid([
        ('Inno Setup Installer (Windows)',
         'Run PasswordManager-Setup-1.0.0.exe. Installs to Program Files, '
         'creates Start Menu entries and optional desktop shortcut. '
         'Uninstaller available from Control Panel.',
         'RECOMMENDED'),
        ('Docker / docker-compose',
         'Use the provided docker-compose.yml for server or headless deployments. '
         'Mount a volume for vault persistence. See Chapter 5.',
         'SERVER DEPLOY'),
        ('Manual Build',
         'Clone the repository and run make build. '
         'Copy the binary to any location. Set VAULT_PATH to control vault placement.',
         'ADVANCED'),
        ('Makefile targets',
         'make run — build and launch\nmake build — binary only\n'
         'make test — run test suite\nmake clean — remove build artifacts',
         'DEVELOPER'),
    ])

    pdf.section_label('Environment Variables')
    pdf.h2('Runtime configuration.')
    pdf.dark_table(
        ['Variable', 'Default', 'Description'],
        [
            ['VAULT_PATH', 'OS config dir', 'Override vault file location'],
            ['PM_LOG_LEVEL', 'info', 'Log verbosity: debug | info | warn | error'],
            ['PM_AUTO_LOCK', '15', 'Idle auto-lock timeout in minutes'],
            ['PM_CLIP_TIMEOUT', '30', 'Clipboard auto-clear delay in seconds'],
            ['PM_MAX_SESSIONS', '1', 'Concurrent sessions allowed per user'],
            ['PM_SESSION_MAX', '480', 'Hard session ceiling in minutes (8 h)'],
            ['PM_LOCKOUT_ATTEMPTS', '5', 'Failed login attempts before lockout'],
            ['PM_LOCKOUT_DURATION', '15', 'Lockout duration in minutes'],
        ],
        col_widths=[52, 38, 92]
    )

    pdf.section_label('Directory Layout')
    pdf.h2('File locations after installation.')
    pdf.code_block(
        'Windows:\n'
        '  C:\\Program Files\\Password Manager\\password-manager.exe\n'
        '  %APPDATA%\\PasswordManager\\vault.pwm\n'
        '  %APPDATA%\\PasswordManager\\vault.pwm.audit\n'
        '  %APPDATA%\\PasswordManager\\vault.pwm.users\n\n'
        'Linux / macOS:\n'
        '  ~/.config/PasswordManager/vault.pwm\n'
        '  ~/.config/PasswordManager/vault.pwm.audit'
    )

    pdf.section_label('First-Run Walkthrough')
    pdf.h2('What happens on initial launch.')
    pdf.bullets([
        'The application checks for an existing vault.pwm file.',
        'If none exists, the Vault Creation wizard appears — choose a vault key.',
        'After vault creation, the Registration screen appears. '
        'The first account created is automatically promoted to Administrator.',
        'MFA enrollment is prompted immediately after first login. '
        'You can skip it, but it is strongly recommended.',
        'After MFA setup the main vault UI opens, ready to add secrets.',
    ])

    pdf.callout(
        'The vault key and master password are separate credentials. '
        'The vault key encrypts the file; the master password authenticates your user account. '
        'Both are required for full access.',
        danger=False
    )


def build_ch4(pdf):
    pdf.chapter_opener('4', 'User Manual',
                       'A complete guide to every screen, feature, and setting.')

    # 4.1 Login & Registration
    pdf.section_label('4.1  Login & Registration')
    pdf.h2('Authentication screens.')

    pdf.h3('Login')
    pdf.body(
        'The login screen presents three fields: Username, Password, and (conditionally) '
        'MFA Code. The MFA field appears automatically once a valid username is entered '
        'and that account has MFA enabled. Submit with the Login button or press Enter.'
    )
    pdf.dark_table(
        ['Field', 'Requirement', 'Notes'],
        [
            ['Username', 'Minimum 3 characters', 'Case-sensitive'],
            ['Password', 'Min 12 chars, upper + lower + digit + special', 'Hidden by default'],
            ['MFA Code', '6-digit numeric TOTP', 'Only shown when account has MFA enabled'],
        ],
        col_widths=[38, 82, 62]
    )

    pdf.h3('Password Strength Meter  (new in v1.0.0)')
    pdf.body(
        'The registration and change-password screens display a 5-segment colour bar '
        'beneath the password field. Segments light up as complexity requirements are met:'
    )
    pdf.bullets([
        'Segment 1 (red)  —  At least 8 characters',
        'Segment 2 (orange)  —  Contains digits',
        'Segment 3 (yellow)  —  Contains uppercase letters',
        'Segment 4 (teal)  —  Contains special characters',
        'Segment 5 (green)  —  12+ characters — full policy compliance',
    ])

    pdf.h3('Reveal Password Toggle  (new in v1.0.0)')
    pdf.body(
        'An eye icon sits at the right edge of every password input field. '
        'Clicking it toggles between masked (●●●●●) and '
        'plaintext display. The toggle state is per-field and resets on navigation.'
    )

    pdf.h3('Account Lockout')
    pdf.body(
        'Five consecutive failed login attempts trigger a 15-minute account lockout. '
        'The lockout duration and threshold are configurable via Security Policy in the '
        'Admin Dashboard or via environment variables PM_LOCKOUT_ATTEMPTS and PM_LOCKOUT_DURATION.'
    )
    pdf.callout(
        'During lockout, the login screen shows the remaining unlock time. '
        'Administrators can manually unlock accounts from the Admin Dashboard → Users tab.',
        danger=True
    )

    # 4.2 Vault & Secrets
    pdf.section_label('4.2  Vault & Secrets')
    pdf.h2('Managing your credentials.')

    pdf.h3('Sidebar Navigation')
    pdf.bullets([
        'Secrets  —  browsable list of all stored secrets',
        'Search  —  full-text search with category filters',
        'Add Secret  —  create a new encrypted credential entry',
        'Settings  —  theme, font size, clipboard timeout, auto-lock',
        'Admin Dashboard  —  visible to Administrators and Security Officers only',
        'Lock Vault  —  immediately locks and requires re-authentication',
        'Logout  —  ends the session and clears in-memory keys',
    ])

    pdf.h3('Add Secret Form')
    pdf.dark_table(
        ['Field', 'Required', 'Notes'],
        [
            ['Name', 'Yes', 'Identifier displayed in the secrets list'],
            ['Username / Email', 'No', 'Associated login identity'],
            ['Password', 'Yes', 'Can be manually entered or generated'],
            ['URL', 'No', 'Service URL for reference'],
            ['Category', 'No', 'login | api | wifi | server | database | other'],
            ['Tags', 'No', 'Comma-separated keywords for search'],
            ['Notes', 'No', 'Multi-line free-form text (also encrypted)'],
        ],
        col_widths=[42, 22, 118]
    )

    pdf.h3('Password Generator')
    pdf.body(
        'Clicking Generate in the Add Secret form produces a cryptographically random '
        '20-character password using Go\'s crypto/rand package. '
        'The generated password is immediately populated into the password field '
        'and evaluated by the strength meter.'
    )

    pdf.h3('Search Bar  (enhanced in v1.0.0)')
    pdf.body(
        'The search bar features a magnifier icon on the left and a clear (X) button '
        'on the right. Below the input sits a horizontal-scrolling row of category chips '
        '(All / Login / API / Wi-Fi / Server / Database / Other). '
        'Selecting a chip instantly filters the secrets list to that category. '
        'Text search and category chip filters compose: applying both narrows results to '
        'secrets matching the text within the selected category.'
    )

    pdf.h3('Copy to Clipboard')
    pdf.body(
        'Each secret row has a Copy button. Clicking it places the password on the '
        'clipboard and starts a 30-second countdown. After 30 seconds the clipboard '
        'is automatically overwritten with an empty string. '
        'The timeout is configurable (PM_CLIP_TIMEOUT).'
    )

    pdf.h3('Status & Role Badges  (new in v1.0.0)')
    pdf.body(
        'Throughout the application, user status and role are shown as colour-coded pill labels:'
    )
    pdf.dark_table(
        ['Badge', 'Color', 'Meaning'],
        [
            ['Administrator', 'Red', 'Full system access'],
            ['Security Officer', 'Amber', 'Audit and policy management'],
            ['Standard User', 'Teal', 'Secrets read/write access'],
            ['Read-Only', '—', 'View secrets only, no write'],
            ['Active', 'Green', 'Account in good standing'],
            ['Revoked', 'Red', 'Access permanently suspended'],
        ],
        col_widths=[50, 30, 102]
    )

    # 4.3 Settings & Appearance
    pdf.section_label('4.3  Settings & Appearance  —  New in v1.0.0')
    pdf.h2('Personalise your workspace.')

    pdf.card_grid([
        ('Dark / Light Mode',
         'Default: Dark. Toggle between the dark theme (#0d1117 background, #e6edf3 text) '
         'and the light theme (#f6f8fa background, #1f2328 text). '
         'Change takes effect immediately across all open windows. '
         'Primary accent colour adapts: teal in dark mode, blue in light mode.',
         'THEME'),
        ('Font Size',
         'Default: 14 pt. Adjustable from the Settings screen. '
         'Affects all text in the application. Unicode coverage is provided by '
         'Segoe UI on Windows for correct rendering of arrow and symbol characters.',
         'TYPOGRAPHY'),
        ('Clipboard Timeout',
         'Default: 30 seconds. The duration before a copied password is automatically '
         'cleared from the system clipboard. Set to 0 to disable auto-clear '
         '(not recommended for shared machines).',
         'SECURITY'),
        ('Auto-Lock Timeout',
         'Default: 15 minutes. The idle period after which the vault locks and requires '
         'the vault key to reopen. Configurable via Settings or PM_AUTO_LOCK.',
         'SECURITY'),
    ])

    # 4.4 Admin Dashboard
    pdf.section_label('4.4  Admin Dashboard')
    pdf.h2('The control centre for administrators.')
    pdf.body(
        'The Admin Dashboard is accessible from the sidebar by Administrators and '
        'Security Officers. It contains six tabs, each gated by role permissions.'
    )

    pdf.dark_table(
        ['Tab', 'Available To', 'Purpose'],
        [
            ['Users', 'Administrator', 'Create, manage, lock, unlock, delete user accounts'],
            ['Audit Log', 'Administrator, Security Officer', 'Browse and export the tamper-evident event log'],
            ['Sessions', 'Administrator', 'View active sessions, invalidate all'],
            ['Exports', 'Administrator, Security Officer', 'Export audit data and generate compliance reports'],
            ['Security Policy', 'Administrator', 'Configure password, session, and lockout policies'],
            ['Role Permissions', 'Administrator', 'Customise per-role permission grid'],
        ],
        col_widths=[36, 60, 86]
    )

    pdf.h3('Users Tab')
    pdf.body(
        'Displays all registered accounts in a sortable table with columns: '
        'Username, Role, MFA Status, Account Status, Last Login. '
        'Actions available from the toolbar:'
    )
    pdf.bullets([
        'Create User  —  username, email, password, role assignment',
        'Change Role  —  promote or demote between the four roles',
        'Lock / Unlock  —  temporarily suspend or restore access',
        'Revoke Access  —  permanent suspension (cannot be undone without admin action)',
        'Delete User  —  removes the account; associated secrets are reassigned or deleted',
        'Reset MFA  —  forces re-enrollment on next login',
    ])

    pdf.h3('Audit Log Tab  —  Enhanced in v1.0.0')
    pdf.body(
        'The audit log displays every recorded event in reverse-chronological order. '
        'New in this release:'
    )
    pdf.card_grid([
        ('Date / Time Range Picker',
         'A From and To calendar date-picker lets you scope the log to any period. '
         'Useful for incident response and compliance audits.',
         'NEW FILTER'),
        ('Category Quick-Filters',
         'Five filter chips: All · Logins · Failed Logins · Admin Actions · Security. '
         'Chips compose with the date range filter.',
         'NEW FILTER'),
        ('Chain Integrity Status Bar',
         'A status bar at the bottom of the audit tab shows the HMAC chain verification '
         'result: OK (teal) or TAMPERED (red). Auto-refreshes every 5 seconds.',
         'NEW FEATURE'),
        ('Export Formats',
         'Export the filtered or full log as JSON (machine-readable), '
         'CSV (spreadsheet), or CEF (ArcSight SIEM format).',
         'EXPORT'),
    ])

    pdf.h3('Sessions Tab')
    pdf.body(
        'Lists all active sessions with: Session ID (abbreviated), Username, '
        'Last Activity, Expiration Time, and Status. '
        'The Invalidate All Sessions button immediately terminates every active session '
        'across all users. Use during security incidents.'
    )

    pdf.h3('Exports Tab')
    pdf.body('Generate compliance reports and vault backups.')
    pdf.bullets([
        'Export Audit Log  —  JSON / CSV / CEF format selection, date-range scoped',
        'Compliance Report  —  PASS / FAIL / WARN across 5 sections: '
        'Encryption, Password Policy, Session Management, Audit, MFA',
        'Vault Backup  —  Encrypted timestamped .pwm.bak snapshot with in-app restore picker',
    ])

    pdf.h3('Security Policy Tab')
    pdf.bullets([
        'Password Policy: minimum length (default 12), complexity requirements, expiry, reuse prevention',
        'Session Policy: idle timeout (default 15 min), hard ceiling (default 8 h), '
        'concurrent sessions (default 1)',
        'Lockout Policy: attempt threshold (default 5), lockout duration (default 15 min)',
    ])

    pdf.h3('Role Permissions Tab  —  New in v1.0.0')
    pdf.body(
        'A checkbox grid showing all 17 permissions mapped to the four roles. '
        'Administrators can modify the defaults and click Save to apply changes immediately '
        'to all active sessions. Reset to Defaults restores the factory permission matrix.'
    )

    # Permission grid
    permissions = [
        'ViewSecrets', 'CreateSecrets', 'EditSecrets', 'DeleteSecrets', 'ShareSecrets',
        'ExportSecrets', 'ViewUsers', 'CreateUsers', 'EditUsers', 'DeleteUsers',
        'ManageRoles', 'ViewAuditLog', 'ExportAuditLog', 'ManagePolicy',
        'ViewSessions', 'ManageSessions', 'SystemAdmin',
    ]
    grid_headers = ['Permission', 'Administrator', 'Security Officer', 'Standard User', 'Read-Only']
    # A=all, S=security, U=standard, R=read-only  (1=yes, 0=no)
    perms_matrix = {
        'ViewSecrets':     [1, 1, 1, 1],
        'CreateSecrets':   [1, 0, 1, 0],
        'EditSecrets':     [1, 0, 1, 0],
        'DeleteSecrets':   [1, 0, 0, 0],
        'ShareSecrets':    [1, 0, 1, 0],
        'ExportSecrets':   [1, 1, 0, 0],
        'ViewUsers':       [1, 1, 0, 0],
        'CreateUsers':     [1, 0, 0, 0],
        'EditUsers':       [1, 0, 0, 0],
        'DeleteUsers':     [1, 0, 0, 0],
        'ManageRoles':     [1, 0, 0, 0],
        'ViewAuditLog':    [1, 1, 0, 0],
        'ExportAuditLog':  [1, 1, 0, 0],
        'ManagePolicy':    [1, 0, 0, 0],
        'ViewSessions':    [1, 1, 0, 0],
        'ManageSessions':  [1, 0, 0, 0],
        'SystemAdmin':     [1, 0, 0, 0],
    }
    grid_rows = []
    for p in permissions:
        vals = perms_matrix[p]
        grid_rows.append([p] + ['Yes' if v else '-' for v in vals])
    pdf.dark_table(grid_headers, grid_rows, col_widths=[52, 38, 42, 36, 14])

    # 4.5 Resizable Columns
    pdf.section_label('4.5  Resizable Columns  —  New in v1.0.0')
    pdf.h2('Adjust column widths in all table views.')
    pdf.body(
        'Every tabular view in the Admin Dashboard (Users, Audit Log, Sessions, Exports) '
        'supports drag-to-resize column dividers. Hover over the divider between two column '
        'headers until the resize cursor appears, then click and drag to adjust.'
    )
    pdf.bullets([
        'Resize operations are throttled to 60 fps for smooth performance.',
        'Column widths persist for the duration of the session.',
        'Double-click a divider to auto-fit the column to its widest content.',
        'Minimum column width: 40 px. There is no maximum.',
    ])


def build_ch5(pdf):
    pdf.chapter_opener('5', 'Deployment Guide',
                       'Local desktop, Docker, docker-compose, and production hardening.')

    pdf.section_label('Deployment Modes')
    pdf.card_grid([
        ('Local Desktop',
         'The primary and recommended deployment. Install via Inno Setup (Windows) '
         'or build from source (Linux/macOS). Vault file lives in the OS config directory.',
         'STANDARD'),
        ('Docker',
         'Run headless or in a containerised environment. '
         'Mount a volume at /app/data for vault persistence.',
         'SERVER'),
        ('docker-compose',
         'Use the included docker-compose.yml for multi-service orchestration. '
         'Suitable for team deployments with shared vault access over a network.',
         'TEAM'),
        ('Manual Binary',
         'Copy the compiled binary anywhere and set VAULT_PATH to control vault placement. '
         'Useful for portable USB deployments.',
         'PORTABLE'),
    ])

    pdf.section_label('Docker')
    pdf.h2('Container deployment.')
    pdf.code_block(
        '# Build image\n'
        'docker build -t password-manager:1.0.0 .\n\n'
        '# Run with persistent vault\n'
        'docker run -d \\\n'
        '  -v /secure/vault:/app/data \\\n'
        '  -e VAULT_PATH=/app/data/vault.pwm \\\n'
        '  -p 8080:8080 \\\n'
        '  password-manager:1.0.0'
    )

    pdf.section_label('docker-compose')
    pdf.h2('Multi-service orchestration.')
    pdf.code_block(
        '# docker-compose.yml (excerpt)\n'
        'version: "3.9"\n'
        'services:\n'
        '  password-manager:\n'
        '    image: password-manager:1.0.0\n'
        '    volumes:\n'
        '      - vault_data:/app/data\n'
        '    environment:\n'
        '      - VAULT_PATH=/app/data/vault.pwm\n'
        '      - PM_MAX_SESSIONS=3\n'
        'volumes:\n'
        '  vault_data:'
    )

    pdf.section_label('Production Hardening')
    pdf.h2('Recommended security settings for production.')
    pdf.bullets([
        'Set PM_LOCKOUT_ATTEMPTS=3 to reduce brute-force window.',
        'Set PM_SESSION_MAX=120 (2 hours) for high-security environments.',
        'Enable PM_CLIP_TIMEOUT=15 for machines with other users.',
        'Schedule daily vault backup exports to an encrypted offsite location.',
        'Run the 13-item automated security test suite after any configuration change.',
        'Restrict file system permissions on vault.pwm to 0600 (owner read/write only).',
        'Enable SIEM integration by exporting audit logs in CEF format to ArcSight or Splunk.',
    ])

    pdf.section_label('Backup Strategy')
    pdf.h2('Protect your vault data.')
    pdf.numbered_step(1, 'In-app backup (daily)',
                      'Admin Dashboard → Exports → Vault Backup. '
                      'Creates an encrypted .pwm.bak file with a timestamp.',
                      'TIER 1')
    pdf.numbered_step(2, 'Offsite copy (weekly)',
                      'Copy the .pwm.bak files to an encrypted external drive or secure cloud bucket. '
                      'The backup file is independently encrypted and safe to store externally.',
                      'TIER 2')
    pdf.numbered_step(3, 'Disaster recovery test (monthly)',
                      'Restore a .pwm.bak via Admin Dashboard → Exports → Restore Backup '
                      'to verify integrity before you actually need it.',
                      'TIER 3')


def build_ch6(pdf):
    pdf.chapter_opener('6', 'Architecture',
                       'Package structure, vault file format, and cryptographic design.')

    pdf.section_label('Package Structure')
    pdf.h2('Go module layout.')
    pdf.code_block(
        'password-manager/\n'
        '├─ cmd/\n'
        '│   ├─ password-manager/main.go    # Application entry point\n'
        '│   └─ security-check/             # Standalone audit validator\n'
        '├─ internal/\n'
        '│   ├─ admin/     # CRUD, policy, compliance, session, revocation\n'
        '│   ├─ audit/     # HMAC-chained log, query engine, SIEM export\n'
        '│   ├─ auth/      # MFA, password policy, RBAC permissions\n'
        '│   ├─ crypto/    # Argon2id, AES-256-GCM, key rotation\n'
        '│   ├─ models/    # User, Secret, AuditLog, Session types\n'
        '│   ├─ secrets/   # SecretManager, encryption, clipboard\n'
        '│   ├─ ui/        # Fyne screens and components\n'
        '│   ├─ updater/   # GitHub release auto-update\n'
        '│   └─ vault/     # File persistence, KDF, backup, shared creds\n'
        '├─ docs/          # This manual and generation script\n'
        '├─ installer/     # Inno Setup .iss script\n'
        '└─ deploy/        # Dockerfile, docker-compose.yml'
    )

    pdf.section_label('Vault File Format')
    pdf.h2('.pwm binary layout.')
    pdf.body(
        'The vault file uses a custom binary format with atomic write semantics. '
        'All writes use a write-to-temp-then-rename pattern followed by fsync to prevent '
        'partial writes from corrupting the vault.'
    )
    pdf.dark_table(
        ['Offset', 'Size', 'Field', 'Description'],
        [
            ['0', '4 bytes', 'Magic', '0x504D5643 ("PMVC") — format identifier'],
            ['4', '4 bytes', 'Version', 'File format version (current: 1)'],
            ['8', '16 bytes', 'Salt', 'Argon2id KDF salt (random, per-vault)'],
            ['24', '12 bytes', 'Nonce', 'AES-GCM nonce for master key encryption'],
            ['36', '32 bytes', 'Auth tag', 'GCM authentication tag'],
            ['68', 'variable', 'Payload', 'AES-256-GCM encrypted JSON blob'],
        ],
        col_widths=[18, 20, 30, 114]
    )

    pdf.section_label('Cryptographic Choices')
    pdf.h2('Why these algorithms.')
    pdf.card_grid([
        ('Argon2id — Key Derivation',
         'Parameters: time=3, memory=64 MB, parallelism=4, output=32 bytes. '
         'Argon2id was the winner of the Password Hashing Competition (2015). '
         'Memory-hard design defeats GPU and ASIC attacks. '
         'The 64 MB memory requirement makes parallelised cracking expensive.',
         'KDF'),
        ('AES-256-GCM — Encryption',
         'Authenticated encryption: confidentiality + integrity in a single primitive. '
         'The 256-bit key provides 128-bit security against Grover\'s quantum search. '
         'GCM authentication tag detects any tampering before decryption.',
         'CIPHER'),
        ('HMAC-SHA256 — Audit Chain',
         'Each audit entry\'s hash is computed over (entry_data || previous_hash). '
         'Any insertion, deletion, or modification breaks the chain. '
         'Verification is O(n) and runs on every audit tab load.',
         'INTEGRITY'),
        ('TOTP RFC 6238 — MFA',
         '30-second time windows with ±1 step tolerance (covers 90-second clock skew). '
         'HMAC-SHA1 per the RFC standard. '
         'Base32 secrets are stored encrypted in the vault, never in plaintext.',
         'MFA'),
    ])

    pdf.section_label('Key Rotation')
    pdf.h2('90-day automatic key rotation.')
    pdf.body(
        'The crypto/key_manager.go module tracks key creation timestamps. '
        'After 90 days, the application prompts for re-encryption with a fresh key. '
        'Old key versions are retained (versioned) for decrypting historical entries '
        'and are securely wiped after successful migration. '
        'Key metadata is stored encrypted in key_storage.go with 0600 file permissions.'
    )


def build_ch7(pdf):
    pdf.chapter_opener('7', 'Password Management',
                       'Secrets lifecycle, history, generator, and shared credentials.')

    pdf.section_label('Secret Structure')
    pdf.h2('What a secret contains.')
    pdf.dark_table(
        ['Field', 'Type', 'Encrypted', 'Description'],
        [
            ['ID', 'UUID', 'No', 'Unique identifier (not sensitive)'],
            ['Name', 'string', 'Yes', 'Human-readable label'],
            ['Username', 'string', 'Yes', 'Associated login identity'],
            ['Password', 'string', 'Yes', 'The credential — AES-256-GCM per entry'],
            ['URL', 'string', 'Yes', 'Service URL'],
            ['Category', 'enum', 'Yes', 'login|api|wifi|server|database|other'],
            ['Tags', '[]string', 'Yes', 'Search keywords'],
            ['Notes', 'string', 'Yes', 'Free-form text'],
            ['CreatedAt', 'timestamp', 'No', 'Creation time (UTC)'],
            ['UpdatedAt', 'timestamp', 'No', 'Last modification time'],
            ['CreatedBy', 'string', 'No', 'Username of creator'],
        ],
        col_widths=[28, 24, 22, 108]
    )

    pdf.callout(
        'Per-entry encryption means the password field of each secret uses an '
        'independently derived AES-256-GCM key. An attacker who extracts one entry\'s '
        'key gains access to only that entry.'
    )

    pdf.section_label('Password History')
    pdf.h2('Automatic change tracking.')
    pdf.body(
        'Every time a password is changed, the previous value is archived in the '
        'password history with timestamp, the username who made the change, and the '
        'reason (if provided). History entries are individually encrypted. '
        'Password reuse prevention checks the history before accepting a new password.'
    )

    pdf.section_label('Password Generator')
    pdf.h2('Cryptographically strong passwords on demand.')
    pdf.bullets([
        'Source: Go crypto/rand (OS CSPRNG)',
        'Default length: 20 characters',
        'Character set: uppercase + lowercase + digits + special symbols',
        'Generated password is immediately strength-evaluated and displayed in the meter',
        'Clicking Generate replaces the current password field content',
    ])

    pdf.section_label('Shared Credentials')
    pdf.h2('Multi-user credential sharing.')
    pdf.body(
        'Administrators can share a secret with other users using the Share feature. '
        'Shared access can be time-limited with an optional expiry datetime. '
        'The recipient sees the shared secret in their vault with a "Shared" badge. '
        'The original owner retains full control and can revoke sharing at any time.'
    )

    pdf.section_label('Import & Export')
    pdf.h2('Moving secrets in and out of the vault.')
    pdf.card_grid([
        ('Import',
         'Import from CSV (compatible with Bitwarden, 1Password, LastPass export formats). '
         'Duplicate detection prevents overwriting existing entries with the same name.',
         'INBOUND'),
        ('Export',
         'Export your secrets to an encrypted ZIP containing a JSON manifest. '
         'The export file is AES-256-GCM encrypted with a user-provided export password.',
         'OUTBOUND'),
    ])


def build_ch8(pdf):
    pdf.chapter_opener('8', 'Security',
                       'Requirements, automated testing, and threat model.')

    pdf.section_label('Security Requirements')
    pdf.h2('Requirement mapping to implementation.')

    reqs = [
        ('3.1  Authentication',
         'Multi-factor authentication (TOTP RFC 6238) enforced at login. '
         'Argon2id password hashing. Account lockout after 5 failed attempts.'),
        ('3.2  RBAC',
         '4 roles with 17 granular permissions. Role assignments stored encrypted. '
         'Permission checks enforced at service layer, not only UI.'),
        ('3.3  Password Management',
         'Per-entry AES-256-GCM encryption. Password history with reuse prevention. '
         'Minimum 12-character policy with complexity requirements.'),
        ('3.4  Architecture',
         'Local-first storage. No remote data transmission. '
         'Atomic vault writes. 90-day automatic key rotation.'),
        ('3.5  Audit & Compliance',
         'HMAC-SHA256 chained audit log. 24 auditable action constants. '
         '365-day retention. JSON/CSV/CEF/Syslog export for SIEM.'),
        ('3.6  Session Management',
         '15-minute idle auto-lock. 8-hour hard session ceiling. '
         '1 concurrent session per user (configurable). '
         'Cryptographically random session tokens.'),
    ]
    for req, impl in reqs:
        pdf.card(req, impl)

    pdf.section_label('Automated Security Tests')
    pdf.h2('13-item test suite in admin/security_testing.go.')
    pdf.dark_table(
        ['Test', 'Area', 'Pass Criteria'],
        [
            ['Auth-01', 'Authentication', 'Argon2id used for all password hashes'],
            ['Auth-02', 'Authentication', 'Lockout triggers after configured threshold'],
            ['Auth-03', 'MFA', 'TOTP window ±1 step tolerance enforced'],
            ['RBAC-01', 'Access Control', 'Permission check enforced at service layer'],
            ['RBAC-02', 'Access Control', 'Role downgrade removes higher permissions'],
            ['Crypto-01', 'Encryption', 'AES-256-GCM used for all secret fields'],
            ['Crypto-02', 'Key Management', 'Key rotation triggered after 90 days'],
            ['Audit-01', 'Audit', 'HMAC chain intact after 1000 entries'],
            ['Audit-02', 'Audit', 'Tampered entry detected within 1 verification'],
            ['Session-01', 'Sessions', 'Idle timeout enforced within ±30 s'],
            ['Session-02', 'Sessions', 'Concurrent session limit enforced'],
            ['Vault-01', 'Persistence', 'Atomic write: partial write does not corrupt'],
            ['Vault-02', 'Persistence', 'Backup restore produces identical vault hash'],
        ],
        col_widths=[22, 32, 128]
    )

    pdf.section_label('Threat Model')
    pdf.h2('Threats considered and mitigations applied.')
    pdf.comparison_table(
        'Threat', 'Mitigation',
        [
            ('Vault file theft (offline attack)',
             'Argon2id KDF makes brute-force computationally infeasible. '
             'Per-entry encryption limits blast radius.'),
            ('Credential stuffing / brute force',
             'Account lockout after 5 attempts. TOTP MFA as second factor.'),
            ('Privilege escalation',
             'RBAC permissions enforced at service layer. '
             'Role changes require Administrator and are fully audited.'),
            ('Audit log tampering',
             'HMAC-SHA256 chain: any modification breaks integrity check immediately.'),
            ('Session hijacking',
             'Cryptographically random tokens, short idle timeout, '
             'single-session enforcement.'),
            ('Clipboard snooping',
             '30-second auto-clear overwrites clipboard contents after copy.'),
            ('Insider threat',
             'Full audit trail of all secret accesses. '
             'Export and bulk operations require Administrator role.'),
        ]
    )

    pdf.section_label('Manual Security Checklist')
    pdf.h2('Post-deployment verification.')
    pdf.bullets([
        'Run the 13-item automated test suite from Admin Dashboard → Security Policy',
        'Verify audit log chain integrity from Admin Dashboard → Audit Log',
        'Confirm vault file permissions are 0600 (owner only)',
        'Test account lockout by attempting 6 failed logins',
        'Verify MFA is enforced: attempt login without TOTP code on an MFA-enabled account',
        'Confirm clipboard clears after 30 seconds following a copy action',
        'Test backup restore from Admin Dashboard → Exports → Restore Backup',
        'Verify role permissions: log in as Standard User and confirm admin tab is hidden',
    ])


def build_ch9(pdf):
    pdf.chapter_opener('9', 'File Manifest & Reference',
                       'Complete source map, role permissions, and environment variable index.')

    pdf.section_label('UI Source Files')
    pdf.h2('internal/ui/ — User interface layer.')
    pdf.dark_table(
        ['File', 'Description'],
        [
            ['ui.go', 'AppUI coordinator — wires screens and manages navigation'],
            ['ui_config.go', 'Default settings: theme, font size, window size, timeouts'],
            ['font_theme.go', 'Segoe UI Unicode theme; dark/light toggle; colour palettes'],
            ['ui_helpers.go', 'Shared button styles, label styles, and layout utilities'],
            ['local_vault_ui.go', 'Main 1100-line vault UI: sidebar, inactivity lock, MFA flow'],
            ['login_ui.go', 'Login form with TOTP field and lockout display'],
            ['register_ui.go', 'Registration form with password strength meter'],
            ['reset_password_ui.go', 'Password change flow; triggers vault re-lock'],
            ['secrets_ui.go', 'Secrets list: icon, name, category, copy, delete'],
            ['add_secret.go', 'Add Secret form with inline password generator'],
            ['admin_dashboard.go', 'Six-tab admin view: users, audit, sessions, exports, policy, perms'],
            ['admin_users.go', 'User management: role dropdown, revoke, delete'],
            ['admin_exports.go', 'Audit export (JSON/CSV/CEF) and compliance report UI'],
            ['session_ui.go', 'Active sessions display and invalidate-all action'],
            ['resizable_cols.go', 'Drag-to-resize column dividers for all table views (60 fps)'],
        ],
        col_widths=[54, 128]
    )

    pdf.section_label('Core Engine Source Files')
    pdf.h2('internal/ — Business logic and data layer.')
    pdf.dark_table(
        ['Package', 'Key Files', 'Responsibility'],
        [
            ['vault', 'vault.go, user.go, audit_integration.go, settings_persistence.go',
             'Encryption, KDF, atomic writes, user auth, settings'],
            ['crypto', 'crypto.go, key_manager.go, key_storage.go, tls_config.go',
             'Argon2id, AES-GCM, 90-day key rotation, TLS 1.2+'],
            ['auth', 'mfa.go, password_policy.go, permissions.go, config.go',
             'TOTP RFC 6238, policy enforcement, RBAC constants'],
            ['admin', 'admin.go, admin_policy.go, compliance.go, security_testing.go',
             'User CRUD, access revocation, compliance report, 13 tests'],
            ['audit', 'audit.go, query.go, siem.go',
             'HMAC-chained log, multi-field query, JSON/CSV/CEF/Syslog'],
            ['secrets', 'secrets.go, secret_service.go, encryption.go, clipboard.go',
             'SecretManager, RBAC wrapper, per-entry crypto, clipboard'],
            ['models', 'models.go', 'User, Secret, AuditLog, Session, Role type definitions'],
        ],
        col_widths=[22, 78, 82]
    )

    pdf.section_label('Full Permission Reference')
    pdf.h2('17 permissions across 4 roles.')
    permissions = [
        ('ViewSecrets',    'View stored secrets',                  1, 1, 1, 1),
        ('CreateSecrets',  'Add new secrets to the vault',         1, 0, 1, 0),
        ('EditSecrets',    'Modify existing secrets',              1, 0, 1, 0),
        ('DeleteSecrets',  'Permanently delete secrets',           1, 0, 0, 0),
        ('ShareSecrets',   'Share secrets with other users',       1, 0, 1, 0),
        ('ExportSecrets',  'Export secrets to encrypted archive',  1, 1, 0, 0),
        ('ViewUsers',      'View user account list',               1, 1, 0, 0),
        ('CreateUsers',    'Register new user accounts',           1, 0, 0, 0),
        ('EditUsers',      'Modify user account details',          1, 0, 0, 0),
        ('DeleteUsers',    'Remove user accounts',                 1, 0, 0, 0),
        ('ManageRoles',    'Assign and change user roles',         1, 0, 0, 0),
        ('ViewAuditLog',   'Browse the audit event log',           1, 1, 0, 0),
        ('ExportAuditLog', 'Export audit log data',                1, 1, 0, 0),
        ('ManagePolicy',   'Configure security policies',          1, 0, 0, 0),
        ('ViewSessions',   'View active user sessions',            1, 1, 0, 0),
        ('ManageSessions', 'Invalidate sessions',                  1, 0, 0, 0),
        ('SystemAdmin',    'Full system administration access',    1, 0, 0, 0),
    ]
    rows = [[p[0], 'Yes' if p[2] else '-',
             'Yes' if p[3] else '-',
             'Yes' if p[4] else '-',
             'Yes' if p[5] else '-', p[1]]
            for p in permissions]
    pdf.dark_table(
        ['Permission', 'Admin', 'Sec. Officer', 'Std. User', 'Read-Only', 'Description'],
        rows,
        col_widths=[38, 16, 22, 18, 18, 70]
    )

    pdf.section_label('Environment Variables — Full Index')
    pdf.h2('All supported runtime configuration variables.')
    pdf.dark_table(
        ['Variable', 'Default', 'Description'],
        [
            ['VAULT_PATH', 'OS config dir', 'Absolute path to vault.pwm file'],
            ['PM_LOG_LEVEL', 'info', 'debug | info | warn | error'],
            ['PM_AUTO_LOCK', '15', 'Idle auto-lock timeout (minutes)'],
            ['PM_CLIP_TIMEOUT', '30', 'Clipboard clear delay (seconds); 0 = disabled'],
            ['PM_MAX_SESSIONS', '1', 'Max concurrent sessions per user'],
            ['PM_SESSION_MAX', '480', 'Hard session ceiling (minutes)'],
            ['PM_LOCKOUT_ATTEMPTS', '5', 'Failed logins before lockout'],
            ['PM_LOCKOUT_DURATION', '15', 'Lockout duration (minutes)'],
            ['PM_KEY_ROTATION_DAYS', '90', 'Automatic key rotation interval'],
            ['PM_AUDIT_RETENTION_DAYS', '365', 'Days to retain audit log entries'],
            ['PM_PASSWORD_MIN_LEN', '12', 'Minimum password length'],
            ['PM_PASSWORD_EXPIRY_DAYS', '90', 'Password expiry (0 = disabled)'],
            ['PM_HISTORY_DEPTH', '10', 'Password history entries kept per account'],
        ],
        col_widths=[54, 30, 98]
    )


# ═════════════════════════════════════════════════════════════════════════════
# Main
# ═════════════════════════════════════════════════════════════════════════════

def main():
    print('Building FULL_MANUAL.pdf ...')
    pdf = ManualPDF()
    pdf.set_title('Password Manager — Full Application Manual')
    pdf.set_author('Kagiso Setwaba')
    pdf.set_subject('Password Manager v1.0.0 Documentation')
    pdf.set_creator('generate_manual.py — fpdf2')

    build_cover(pdf)
    build_toc(pdf)
    build_ch1(pdf)
    build_ch2(pdf)
    build_ch3(pdf)
    build_ch4(pdf)
    build_ch5(pdf)
    build_ch6(pdf)
    build_ch7(pdf)
    build_ch8(pdf)
    build_ch9(pdf)

    pdf.output(OUT_PATH)
    print(f'Done — {pdf.page} pages written to {OUT_PATH}')


if __name__ == '__main__':
    main()

import os
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfbase import pdfmetrics


class ReportGenerator:
    def __init__(self, output_path="report/flow_report.pdf"):
        self.output_path = output_path

        font_path = "fonts/DejaVuSans.ttf"
        pdfmetrics.registerFont(TTFont("DejaVuSans", font_path))
        self.styles = getSampleStyleSheet()
        self.styles["Normal"].fontName = "DejaVuSans"
        self.styles["Heading3"].fontName = "DejaVuSans"

    def add_header(self, story, text):
        story.append(Paragraph(f"<b>{text}</b>", self.styles["Heading3"]))
        story.append(Spacer(1, 12))

    def add_table(self, story, title, headers, data):
        self.add_header(story, title)

        table = Table([headers] + data)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.lightgrey),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, -1), 'DejaVuSans'),
            ('FONTNAME', (0, 0), (-1, 0), 'DejaVuSans'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
        ]))

        story.append(table)
        story.append(Spacer(1, 20))

    def generate_pdf(self, stats, pcap_name):
        story = []
        unique_src = stats["unique_hosts_src"]
        unique_dst = stats["unique_hosts_dst"]
        total_flows = stats["total_flows"]

        story.append(Paragraph(f"<b>Statystyki dla pliku: {pcap_name}</b>", self.styles["Heading3"]))
        story.append(Spacer(1, 20))

        self.add_table(
            story,
            "Najwięcej flow między parami hostów",
            ["Adres źródłowy", "Adres docelowy", "Liczba flow", "Liczba pakietów", "Liczba bajtów"],
            stats["top_flows"].values.tolist()
        )

        self.add_table(
            story,
            "Największy transfer bajtów",
            ["Adres źródłowy", "Adres docelowy", "Liczba flow", "Liczba pakietów", "Liczba bajtów"],
            stats["top_bytes"].values.tolist()
        )


        self.add_table(
            story,
            "Najbardziej aktywne hosty źródłowe",
            ["Adres źródłowy", "Liczba flow"],
            stats["most_active_src"].values.tolist()
        )

        self.add_table(
            story,
            "Najbardziej aktywne hosty docelowe",
            ["Adres docelowy", "Liczba flow"],
            stats["most_active_dst"].values.tolist()
        )
        story.append(Paragraph(
            f"Liczba unikalnych hostów źródłowych: <b>{unique_src}</b>",
            self.styles["Normal"]
        ))
        story.append(Paragraph(
            f"Liczba unikalnych hostów docelowych: <b>{unique_dst}</b>",
            self.styles["Normal"]
        ))
        story.append(Paragraph(
            f"Łączna liczba flow: <b>{total_flows}</b>",
            self.styles["Normal"]
        ))

        doc = SimpleDocTemplate(self.output_path, pagesize=A4)
        doc.build(story)

        return self.output_path

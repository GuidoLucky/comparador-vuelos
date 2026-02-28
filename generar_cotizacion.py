"""
Generador de cotizaciones Lucky Tour — versión servidor.
Recibe datos en JSON y genera el PDF.
"""

import sys, json, math, os
from datetime import date
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                 HRFlowable, Image, Table, TableStyle, PageBreak)
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_RIGHT

NAVY     = colors.HexColor('#1B3A5C')
MID_GRAY = colors.HexColor('#CCCCCC')

FEE_TABLE = [
    (0,    599,  25), (600,  999,  30), (1000, 1499, 35),
    (1500, 1999, 40), (2000, 2999, 50), (3000, 3999, 55),
    (4000, 5499, 60), (5500, float('inf'), 80),
]
DESCUENTO_TABLE = [
    (0,   50,  0),  (51,  80,  10), (81,  100, 20), (101, 140, 30),
    (141, 180, 40), (181, 220, 50), (221, 260, 60), (261, float('inf'), 70),
]

CONTACTOS = {
    "guido":   {"nombre": "Guido Finkelstein",   "mail": "Guido@luckytourviajes.com",    "tel": "+54 9 11 6846 3892"},
    "julieta": {"nombre": "Julieta Zubeldia",     "mail": "Julietaz@luckytourviajes.com", "tel": "+54 9 11 3295 5404"},
    "ruthy":   {"nombre": "Ruthy Tuchsznajder",   "mail": "Ventas@luckytourviajes.com",   "tel": "+54 9 11 6847 0985"},
}

def get_fee(neto):
    for low, high, fee in FEE_TABLE:
        if low <= neto <= high:
            return fee
    return 80

def get_descuento(comision):
    for low, high, desc in DESCUENTO_TABLE:
        if low <= comision <= high:
            return desc
    return 70

def redondear_arriba(p):
    return int(math.ceil(p / 5) * 5) if p % 5 != 0 else int(p)

def redondear_abajo(p):
    return int(math.floor(p / 5) * 5)

def calcular_precio(neto, tipo_tarifa='PUB', comision_over=0):
    if tipo_tarifa == 'PNEG' or comision_over <= 50:
        return redondear_arriba(neto + get_fee(neto))
    else:
        return redondear_abajo(neto - get_descuento(comision_over))

def armar_linea_precio(precio, tipo, cantidad, total_pasajeros, hay_multiples_tipos):
    if total_pasajeros == 1:
        return f"USD {precio:,}"
    elif not hay_multiples_tipos:
        return f"USD {precio:,} cada {tipo}"
    else:
        return f"USD {precio:,} cada {tipo}" if cantidad > 1 else f"USD {precio:,} {tipo}"

def _cabecera(logo_path):
    fecha_s = ParagraphStyle('f', fontName='Helvetica', fontSize=9,
                              textColor=colors.HexColor('#666666'), alignment=TA_RIGHT)
    title_s = ParagraphStyle('t', fontName='Helvetica-Bold', fontSize=16,
                              textColor=NAVY, alignment=TA_CENTER, spaceAfter=2*mm)
    elems = [Paragraph(date.today().strftime("%d/%m/%Y"), fecha_s)]
    if os.path.exists(logo_path):
        img = Image(logo_path, width=55*mm, height=46*mm)
        img.hAlign = 'CENTER'
        elems.append(img)
    elems.append(Paragraph("Cotizacion", title_s))
    elems.append(Spacer(1, 2*mm))
    elems.append(HRFlowable(width="100%", thickness=2, color=NAVY, spaceAfter=4*mm))
    return elems

def generar_pdf(opciones_vuelo, vendedor, output_path, logo_path):
    doc = SimpleDocTemplate(output_path, pagesize=A4,
        rightMargin=22*mm, leftMargin=22*mm, topMargin=5*mm, bottomMargin=35*mm)
    story = []

    sec_s    = ParagraphStyle('sec', fontName='Helvetica-Bold', fontSize=9,  textColor=NAVY, spaceBefore=3*mm, spaceAfter=1.5*mm)
    vuelo_s  = ParagraphStyle('v',   fontName='Helvetica-Bold', fontSize=10, textColor=colors.black, spaceAfter=0.5*mm)
    det_s    = ParagraphStyle('d',   fontName='Helvetica',      fontSize=8,  textColor=colors.HexColor('#555555'), spaceAfter=1.5*mm)
    precio_s = ParagraphStyle('p',   fontName='Helvetica-Bold', fontSize=10, textColor=NAVY, spaceAfter=1.5*mm)

    es_multiple = len(opciones_vuelo) > 1

    for i, opcion in enumerate(opciones_vuelo, 1):
        if i > 1:
            story.append(PageBreak())
        story.extend(_cabecera(logo_path))

        vuelos    = opcion['vuelos']
        detalle   = opcion['detalle_vuelo']
        pasajeros = opcion['pasajeros']
        aerolinea = opcion.get('aerolinea', '')

        if es_multiple:
            label = Paragraph(f"  OPCION {i}", ParagraphStyle('op', fontName='Helvetica-Bold',
                              fontSize=10, textColor=colors.white))
            t = Table([[label]], colWidths=[155*mm])
            t.setStyle(TableStyle([
                ('BACKGROUND',    (0,0), (-1,-1), NAVY),
                ('TOPPADDING',    (0,0), (-1,-1), 4),
                ('BOTTOMPADDING', (0,0), (-1,-1), 4),
                ('LEFTPADDING',   (0,0), (-1,-1), 6),
            ]))
            story.append(t)
            story.append(Spacer(1, 2*mm))

        titulo_itin = f"  ITINERARIO - {aerolinea}" if aerolinea else "  ITINERARIO"
        story.append(Paragraph(titulo_itin, sec_s))

        for v in vuelos:
            linea = f"<b>{v['fecha']}</b> &nbsp; {v['origen']} &rarr; {v['destino']} &nbsp;&nbsp; {v['salida']} &rarr; {v['llegada']}"
            story.append(Paragraph(linea, vuelo_s))
            if v.get('numero_vuelo'):
                story.append(Paragraph(v['numero_vuelo'], det_s))

        story.append(Paragraph(detalle, det_s))

        total_pasajeros     = sum(p['cantidad'] for p in pasajeros)
        hay_multiples_tipos = len(pasajeros) > 1
        story.append(Paragraph("  PRECIO" if total_pasajeros == 1 else "  PRECIOS", sec_s))
        for pax in pasajeros:
            precio = calcular_precio(pax['neto'], pax.get('tipo_tarifa', 'PUB'), pax.get('comision_over', 0))
            story.append(Paragraph(
                armar_linea_precio(precio, pax['tipo'], pax['cantidad'], total_pasajeros, hay_multiples_tipos),
                precio_s))

    contacto = CONTACTOS.get(vendedor.lower(), CONTACTOS['guido'])
    def footer(canvas, doc):
        canvas.saveState()
        x, y = 22*mm, 18*mm
        canvas.setLineWidth(1.5)
        canvas.setStrokeColor(NAVY)
        canvas.line(x, y + 3*mm, doc.width + x, y + 3*mm)
        canvas.setFont('Helvetica-Bold', 9)
        canvas.setFillColor(NAVY)
        canvas.drawString(x, y, "Contacto:")
        canvas.drawString(x + 55, y, contacto['nombre'])
        canvas.setFont('Helvetica', 9)
        canvas.setFillColor(colors.HexColor('#333333'))
        canvas.drawString(x, y - 11, contacto['mail'])
        canvas.drawString(x, y - 22, contacto['tel'])
        canvas.restoreState()

    doc.build(story, onFirstPage=footer, onLaterPages=footer)

if __name__ == '__main__':
    data = json.loads(sys.argv[1])
    generar_pdf(
        opciones_vuelo=data['opciones'],
        vendedor=data['vendedor'],
        output_path=data['output_path'],
        logo_path=data['logo_path']
    )
    print('OK')

"""
PDF de Reserva — Lucky Tour
Genera un comprobante de reserva para enviar al cliente.
Usa las mismas reglas de precio de venta que el cotizador.
"""

import json, math, os, sys
from datetime import datetime
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                 HRFlowable, Image, Table, TableStyle)
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.enums import TA_CENTER, TA_RIGHT, TA_LEFT

# ── COLORES ──
NAVY     = colors.HexColor('#1B3A5C')
LIGHT_BG = colors.HexColor('#F5F7FA')
GREEN    = colors.HexColor('#2E7D32')

# ── TABLAS DE FEES Y DESCUENTOS (mismas que cotizador) ──
FEE_TABLE = [
    (0,    599,  25), (600,  999,  30), (1000, 1499, 35),
    (1500, 1999, 40), (2000, 2999, 50), (3000, 3999, 55),
    (4000, 5499, 60), (5500, float('inf'), 80),
]
DESCUENTO_TABLE = [
    (0,   50,  0),  (51,  80,  10), (81,  100, 20), (101, 140, 30),
    (141, 180, 40), (181, 220, 50), (221, 260, 60), (261, float('inf'), 70),
]

# ── CONTACTOS ──
CONTACTOS = {
    "guido":   {"nombre": "Guido Finkelstein",   "mail": "Guido@luckytourviajes.com",    "tel": "+54 9 11 6846 3892"},
    "julieta": {"nombre": "Julieta Zubeldia",     "mail": "Julietaz@luckytourviajes.com", "tel": "+54 9 11 3295 5404"},
    "ruthy":   {"nombre": "Ruthy Tuchsznajder",   "mail": "Ventas@luckytourviajes.com",   "tel": "+54 9 11 6847 0985"},
}

LOGO_PATH = None
for p in ["/app/public/logo_transparent.png", "/app/logo_transparent.png", "/home/claude/logo_transparent.png"]:
    if os.path.exists(p):
        LOGO_PATH = p
        break

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

def calcular_precio(neto, tipo_tarifa='PNEG', comision_over=0):
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


def format_fecha_vuelo(iso_date):
    """Convierte ISO date a formato legible: '28/03'"""
    try:
        dt = datetime.fromisoformat(iso_date.replace('Z', ''))
        meses = ['ene','feb','mar','abr','may','jun','jul','ago','sep','oct','nov','dic']
        return f"{dt.day:02d}/{meses[dt.month-1]}"
    except:
        return iso_date[:10] if iso_date else ''

def format_hora(iso_date):
    """Convierte ISO date a hora: '22.40'"""
    try:
        dt = datetime.fromisoformat(iso_date.replace('Z', ''))
        return f"{dt.hour:02d}.{dt.minute:02d}"
    except:
        return ''

def format_ciudad(code, airports_info):
    """Devuelve 'Ciudad (CODE)' o solo 'CODE'"""
    if airports_info and code in airports_info:
        city = airports_info[code].get('cityName', code)
        return f"{city.title()} ({code})"
    return code


def generar_reserva_pdf(data, output_path):
    doc = SimpleDocTemplate(output_path, pagesize=A4,
        rightMargin=22*mm, leftMargin=22*mm, topMargin=5*mm, bottomMargin=35*mm)
    story = []

    # ── ESTILOS ──
    fecha_s  = ParagraphStyle('f', fontName='Helvetica', fontSize=9, textColor=colors.HexColor('#666666'), alignment=TA_RIGHT)
    title_s  = ParagraphStyle('t', fontName='Helvetica-Bold', fontSize=16, textColor=NAVY, alignment=TA_CENTER, spaceAfter=2*mm)
    sec_s    = ParagraphStyle('sec', fontName='Helvetica-Bold', fontSize=9, textColor=NAVY, spaceBefore=3*mm, spaceAfter=1.5*mm)
    vuelo_s  = ParagraphStyle('v', fontName='Helvetica-Bold', fontSize=10, textColor=colors.black, spaceAfter=0.5*mm)
    det_s    = ParagraphStyle('d', fontName='Helvetica', fontSize=8, textColor=colors.HexColor('#555555'), spaceAfter=1.5*mm)
    precio_s = ParagraphStyle('p', fontName='Helvetica-Bold', fontSize=10, textColor=NAVY, spaceAfter=1.5*mm)
    normal_s = ParagraphStyle('n', fontName='Helvetica', fontSize=9, textColor=colors.black, spaceAfter=1*mm)
    bold_s   = ParagraphStyle('b', fontName='Helvetica-Bold', fontSize=9, textColor=colors.black, spaceAfter=1*mm)
    pnr_s    = ParagraphStyle('pnr', fontName='Helvetica-Bold', fontSize=14, textColor=NAVY, alignment=TA_CENTER, spaceAfter=1*mm)
    sub_s    = ParagraphStyle('sub', fontName='Helvetica', fontSize=9, textColor=colors.HexColor('#666666'), alignment=TA_CENTER, spaceAfter=3*mm)

    # ── CABECERA ──
    pnr = data.get('pnr', '')
    story.append(Paragraph(datetime.now().strftime("%d/%m/%Y"), fecha_s))
    if LOGO_PATH and os.path.exists(LOGO_PATH):
        img = Image(LOGO_PATH, width=55*mm, height=46*mm)
        img.hAlign = 'CENTER'
        story.append(img)
    story.append(Paragraph(f"Confirmación de Reserva — <font size=12>{pnr}</font>", title_s))
    story.append(Spacer(1, 2*mm))
    story.append(HRFlowable(width="100%", thickness=2, color=NAVY, spaceAfter=4*mm))

    # ── PASAJEROS ──
    pasajeros = data.get('pasajeros', [])
    if pasajeros:
        story.append(Paragraph("👥  PASAJEROS", sec_s))
        tipo_labels = {'ADT': 'Adulto', 'CHD': 'Menor', 'CNN': 'Menor', 'INF': 'Infante'}
        for p in pasajeros:
            nombre = p.get('nombre', '')
            tipo = tipo_labels.get(p.get('tipo', 'ADT'), p.get('tipo', ''))
            doc_info = p.get('documento', '')
            linea = f"<b>{nombre}</b> ({tipo})"
            if doc_info:
                linea += f" &nbsp;—&nbsp; {doc_info}"
            story.append(Paragraph(linea, normal_s))
        story.append(Spacer(1, 2*mm))

    # ── ITINERARIO ──
    aerolinea = data.get('aerolinea', '')
    vuelos = data.get('vuelos', [])
    airports = data.get('airports', {})

    titulo_itin = f"✈  ITINERARIO — {aerolinea}" if aerolinea else "✈  ITINERARIO"
    story.append(Paragraph(titulo_itin, sec_s))

    for v in vuelos:
        dep = v.get('departureAirportCode', v.get('origen', ''))
        arr = v.get('arrivalAirportCode', v.get('destino', ''))
        dep_date = v.get('departureDate', '')
        arr_date = v.get('arrivalDate', '')
        flight = v.get('flightNumber', v.get('numero_vuelo', ''))

        fecha = format_fecha_vuelo(dep_date) if dep_date else v.get('fecha', '')
        origen = format_ciudad(dep, airports)
        destino = format_ciudad(arr, airports)
        salida = format_hora(dep_date) if dep_date else v.get('salida', '')
        llegada = format_hora(arr_date) if arr_date else v.get('llegada', '')

        linea = f"<b>{fecha}</b> &nbsp; {origen} → {destino} &nbsp;&nbsp; {salida} → {llegada}"
        story.append(Paragraph(linea, vuelo_s))
        if flight:
            story.append(Paragraph(flight, det_s))

    story.append(Spacer(1, 2*mm))

    # ── PRECIO DE VENTA ──
    precio_data = data.get('precio', {})
    if precio_data and precio_data.get('pasajeros'):
        pax_precios = precio_data['pasajeros']
        total_pax = sum(p.get('cantidad', 1) for p in pax_precios)
        multi_tipos = len(pax_precios) > 1

        story.append(Paragraph("💰  PRECIO" if total_pax == 1 else "💰  PRECIOS", sec_s))

        for pp in pax_precios:
            neto = pp.get('neto', 0)
            tipo_tarifa = pp.get('tipo_tarifa', 'PNEG')
            comision_over = pp.get('comision_over', 0)
            tipo_label = pp.get('tipo', 'adulto')
            cantidad = pp.get('cantidad', 1)

            precio_venta = calcular_precio(neto, tipo_tarifa, comision_over)
            linea = armar_linea_precio(precio_venta, tipo_label, cantidad, total_pax, multi_tipos)
            story.append(Paragraph(linea, precio_s))

    elif precio_data.get('venta'):
        # Precio de venta directo (sin cálculo)
        story.append(Paragraph("💰  PRECIO", sec_s))
        story.append(Paragraph(f"USD {precio_data['venta']:,}", precio_s))

    # ── FOOTER ──
    vendedor = data.get('vendedor', 'guido').lower()
    if vendedor not in CONTACTOS:
        vendedor = 'guido'
    contacto = CONTACTOS[vendedor]

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
    print(f"✅ PDF generado: {output_path}")


if __name__ == '__main__':
    input_path = sys.argv[1] if len(sys.argv) > 1 else '/tmp/reserva_data.json'
    output_path = sys.argv[2] if len(sys.argv) > 2 else '/tmp/reserva.pdf'
    with open(input_path, 'r') as f:
        data = json.load(f)
    generar_reserva_pdf(data, output_path)

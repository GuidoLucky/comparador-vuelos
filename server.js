const express = require('express');
const path = require('path');
const app = express();
app.use(express.json());
app.use(express.static('public'));

// Ruta explícita para reservas.html (fallback si static no lo encuentra)
app.get('/reservas.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'reservas.html'));
});

const PORT = process.env.PORT || 3000;
const SCIWEB_USER = process.env.SCIWEB_USER;
const SCIWEB_PASS = process.env.SCIWEB_PASS;
const API_BASE = 'https://api-gwc.glas.travel/api';
const COMPANY_ID = '3036';
const WHOLESALER_ID = '538';

// DB
const db = require('./db');

// Migración: agregar columnas faltantes
if (db) {
  (async () => {
    try {
      await db.query(`ALTER TABLE reservas ADD COLUMN IF NOT EXISTS notas TEXT`);
      await db.query(`ALTER TABLE reservas ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW()`);
      await db.query(`ALTER TABLE reservas ADD COLUMN IF NOT EXISTS vendedor TEXT`);
      await db.query(`ALTER TABLE reservas ADD COLUMN IF NOT EXISTS precio_venta_usd NUMERIC`);
      console.log('[DB] Migración OK');
    } catch(e) { console.warn('[DB] Migración:', e.message); }
  })();
}

let tokenCache = { token: null, expiry: 0 };

async function getToken() {
  if (tokenCache.token && Date.now() < tokenCache.expiry) return tokenCache.token;
  const body = new URLSearchParams({ mode:'pass', username:SCIWEB_USER, password:SCIWEB_PASS, channel:'GWC', defaultWholesalerId:WHOLESALER_ID });
  const res = await fetch(`${API_BASE}/Account/token`, {
    method:'POST',
    headers:{ 'Content-Type':'application/x-www-form-urlencoded', 'Origin':'https://sciweb.tucanotours.com.ar', 'Referer':'https://sciweb.tucanotours.com.ar/' },
    body: body.toString()
  });
  const data = await res.json();
  const token = data.access_token || data.token || data.Token || data.AccessToken;
  if (!token) throw new Error('No se pudo obtener token: ' + JSON.stringify(data));
  tokenCache = { token, expiry: Date.now() + 50*60*1000 };
  return token;
}

function getHeaders(token) {
  return {
    'Authorization': `Bearer ${token}`,
    'Companyassociationid': COMPANY_ID,
    'Content-Type': 'application/json',
    'Origin': 'https://sciweb.tucanotours.com.ar',
    'Referer': 'https://sciweb.tucanotours.com.ar/'
  };
}

// ─── TIPO DE CAMBIO BSP ───
let tcCache = { bsp: null, expiry: 0 };
app.get('/tipo-cambio', async (req, res) => {
  try {
    if (tcCache.bsp && Date.now() < tcCache.expiry) return res.json({ bsp: tcCache.bsp });
    const r = await fetch('https://jazzoperador.tur.ar/cotizacion-historica/');
    const html = await r.text();
    const rows = html.match(/<tr[^>]*>[\s\S]*?<\/tr>/gi) || [];
    let bsp = null;
    for (const row of rows) {
      const cells = row.match(/<td[^>]*>([\s\S]*?)<\/td>/gi) || [];
      if (cells.length >= 2) {
        const bspText = cells[1].replace(/<[^>]+>/g, '').trim().replace('.', '').replace(',', '.');
        const val = parseFloat(bspText);
        if (!isNaN(val) && val > 100) { bsp = val; break; }
      }
    }
    if (!bsp) bsp = 1425;
    tcCache = { bsp, expiry: Date.now() + 60*60*1000 };
    console.log('[BSP]', bsp);
    res.json({ bsp });
  } catch(e) {
    res.json({ bsp: tcCache.bsp || 1425 });
  }
});

app.get('/health', (req, res) => res.json({ ok:true }));

// ─── BÚSQUEDA DE VUELOS ───
app.post('/buscar-vuelos', async (req, res) => {
  const { tipo, origen, destino, salida, regreso, adultos, ninos, infantes, stops, tramos, moneda } = req.body;
  try {
    const token = await getToken();
    const stopsFilter = (stops !== undefined && stops !== '') ? parseInt(stops) : null;
    const currencyCode = moneda === 'ARS' ? null : 'USD';

    let payload, endpoint, addSearchPayload;

    if (tipo === 'oneway') {
      endpoint = `${API_BASE}/FlightSearch/OnewayRemake`;
      payload = {
        DepartCode: origen, ArrivalCode: destino,
        DepartDate: `${salida}T00:00:00`, DepartTime: null,
        Adults: parseInt(adultos), Childs: parseInt(ninos), Infants: parseInt(infantes),
        CabinType: null, Stops: null, Airlines: [],
        TypeOfFlightAllowedInItinerary: null, SortByGLASAlgorithm: "",
        AlternateCurrencyCode: currencyCode, CorporationCodeGlas: null, IncludeFiltersOptions: true
      };
      addSearchPayload = { SearchTravelType: 2, OneWayModel: payload, MultipleLegsModel: null, RoundTripModel: null };
    } else if (tipo === 'roundtrip') {
      endpoint = `${API_BASE}/FlightSearch/RoundTripRemake`;
      payload = {
        DepartCode: origen, ArrivalCode: destino,
        DepartDate: `${salida}T00:00:00`, ArrivalDate: `${regreso}T00:00:00`,
        ArrivalTime: null, DepartTime: null,
        Adults: parseInt(adultos), Childs: parseInt(ninos), Infants: parseInt(infantes),
        CabinType: null, Stops: null, Airlines: [],
        TypeOfFlightAllowedInItinerary: null, SortByGLASAlgorithm: "",
        AlternateCurrencyCode: currencyCode, CorporationCodeGlas: null, IncludeFiltersOptions: true
      };
      addSearchPayload = { SearchTravelType: 1, OneWayModel: null, MultipleLegsModel: null, RoundTripModel: payload };
    } else if (tipo === 'multidestino') {
      endpoint = `${API_BASE}/FlightSearch/MultipleLegsRemake`;
      const legs = tramos.map((t, i) => ({
        LegNumber: i+1, DepartCode: t.origen, ArrivalCode: t.destino,
        DepartDate: `${t.salida}T00:00:00`, DepartTime: null,
        CabinType: null, Stops: null, Airlines: []
      }));
      payload = {
        Legs: legs, Adults: parseInt(adultos), Childs: parseInt(ninos), Infants: parseInt(infantes),
        TypeOfFlightAllowedInItinerary: null, SortByGLASAlgorithm: "",
        AlternateCurrencyCode: currencyCode, CorporationCodeGlas: null, IncludeFiltersOptions: true
      };
      addSearchPayload = { SearchTravelType: 3, OneWayModel: null, MultipleLegsModel: payload, RoundTripModel: null };
    }

    await fetch(`${API_BASE}/FlightSearchHistory/AddSearch`, {
      method:'POST', headers: getHeaders(token), body: JSON.stringify(addSearchPayload)
    }).catch(()=>{});

    const searchRes = await fetch(endpoint, {
      method:'POST', headers: getHeaders(token), body: JSON.stringify(payload)
    });
    if (!searchRes.ok) throw new Error(`API error: ${searchRes.status} - ${await searchRes.text().then(t=>t.substring(0,300))}`);
    const data = await searchRes.json();
    console.log(`[Vuelos] ${data.minifiedQuotations?.length || 0} resultados`);

    const vuelos = procesarVuelos(data, stopsFilter);
    res.json({ ok:true, vuelos, searchId: data.searchId || data.SearchId });
  } catch(err) {
    console.error('[Vuelos] Error:', err.message);
    if (err.message.includes('401')) tokenCache = { token:null, expiry:0 };
    res.json({ ok:false, error: err.message });
  }
});

function procesarVuelos(data, stopsFilter) {
  if (!data.minifiedQuotations) return [];
  const legsMap = data.minifiedLegs || {};
  const airlinesMap = data.minifiedAirlinesInformation || {};

  return data.minifiedQuotations
    .filter(q => !q.error)
    .map(q => {
      const itinerario = q.legs.map(legId => {
        const leg = legsMap[legId];
        if (!leg) return null;
        const ciudadesEscala = (() => {
          const c = leg.connectingCityCodesList;
          if (!c) return [];
          if (Array.isArray(c)) return c;
          if (typeof c === 'string') return c.split(',').filter(Boolean);
          return [];
        })();
        return {
          legId, origen: leg.originAirportCode, destino: leg.destinationAirportCode,
          salida: leg.departure, llegada: leg.arrival,
          duracionMin: leg.elapsedFlightTimeInMinutes,
          duracion: leg.elapsedFlightTimeInMinutesFormatted,
          escalas: ciudadesEscala.length,
          ciudadesEscala, tripDays: leg.tripDays || 0,
        };
      }).filter(Boolean);

      const bagLeg = q.legsWithBaggageAllowance?.[0]?.baggageAllowance;
      const maxEscalas = itinerario.reduce((max, l) => Math.max(max, l.escalas||0), 0);

      const handOnList = bagLeg?.handOn || [];
      const handOnIncluido = handOnList.some(b => b.chargeType===0 && b.pieces>0);
      const handOnLabel = handOnList.length>0 ? (handOnIncluido?'Incluida':'Con cargo') : 'No informado';

      const carryOnList = bagLeg?.carryOn || [];
      const carryOnItem = carryOnList.find(b => b.chargeType===0 && b.pieces>0);
      const carryOnIncluido = !!carryOnItem;
      const carryOnLabel = carryOnItem ? (`${carryOnItem.weight||''}${carryOnItem.weightUnit||''}`).trim()||'Incluido' : (carryOnList.length>0?'Con cargo':'No incluido');

      const checkedList = (bagLeg?.checked||[]).filter(b=>b.passengerType===0);
      const checkedIncluido = checkedList.some(b=>b.chargeType===0&&(b.pieces>0||(b.weight&&b.weight!=='0')));
      const checkedItem = checkedList.find(b=>b.chargeType===0&&(b.pieces>0||(b.weight&&b.weight!=='0')));
      const checkedLabel = checkedItem ? (checkedItem.pieces>0?`${checkedItem.pieces}x ${checkedItem.weight}${checkedItem.unit}`:`${checkedItem.weight}${checkedItem.unit}`) : 'No incluida';

      return {
        id: q.quotationId, aerolinea: q.validatingCarrier,
        aerolineaDesc: airlinesMap[q.validatingCarrier] || q.sourceDescription || q.source,
        precioUSD: q.grandTotalSellingPriceAmount || 0,
        monedaBase: q.grandTotalSellingPriceCurrency || 'USD',
        expira: q.offerExpirationTimeCTZ, itinerario, escalas: maxEscalas,
        equipaje: {
          handOn: { label: handOnLabel, incluido: handOnIncluido },
          carryOn: { label: carryOnLabel, incluido: carryOnIncluido },
          checked: { label: checkedLabel, incluido: checkedIncluido }
        },
        source: q.source
      };
    })
    .filter(v => stopsFilter === null || v.escalas <= stopsFilter)
    .sort((a,b) => a.precioUSD - b.precioUSD);
}

// ─── RESERVAS ───

// Verificar disponibilidad
app.post('/check-availability', async (req, res) => {
  const { searchId, quotationId } = req.body;
  try {
    const token = await getToken();
    const r = await fetch(`${API_BASE}/FlightItinerary/CheckAvailabilityRemake`, {
      method:'POST', headers: getHeaders(token),
      body: JSON.stringify({ CompanyAssociationId: parseInt(COMPANY_ID), SearchId: searchId, QuotationId: String(quotationId) })
    });
    const text = await r.text();
    let data = {};
    try { data = JSON.parse(text); } catch(e) { console.warn('[CheckAvail] respuesta no-JSON:', text.substring(0,100)); }
    // Si no hay respuesta válida, igual permitir continuar
    res.json({ ok:true, hasDifferences: data.hasDifferences || false });
  } catch(e) {
    console.error('[CheckAvail] Error:', e.message);
    res.json({ ok:false, error: e.message });
  }
});

// Traer países y tipos de documento
app.get('/document-countries', async (req, res) => {
  const { documentFor } = req.query;
  try {
    const token = await getToken();
    const r = await fetch(`${API_BASE}/Documents/GetDocumentCountries?documentFor=${documentFor}&includeDocumentTypes=True`, {
      headers: getHeaders(token)
    });
    const text = await r.text();
    let data = [];
    try { data = JSON.parse(text); } catch(e) { console.warn('[DocCountries] respuesta no-JSON:', text.substring(0,100)); }
    res.json({ ok:true, data: Array.isArray(data) ? data : [] });
  } catch(e) {
    console.error('[DocCountries] Error:', e.message);
    res.json({ ok:false, error: e.message, data: [] });
  }
});

// Crear reserva
app.post('/crear-reserva', async (req, res) => {
  const { searchId, quotationId, pasajeros, contacto, vueloInfo } = req.body;
  try {
    const token = await getToken();

    const ARG_ID = '3144952d-b7f4-4ddf-9ed8-8021bfc67c4b';
    function sv(v) { return (v && v !== 'undefined') ? v : null; }
    function buildPax(p, i, tipo) {
      const typeNum = tipo==='ADT'?0:tipo==='CHD'?1:2;
      return {
        key: `${tipo}${i+1}`, indexUI: i+1, passengerType: typeNum,
        FirstName: p.nombre.toUpperCase(), LastName: p.apellido.toUpperCase(),
        Gender: parseInt(p.genero),
        BirthdateDay: parseInt(p.fechaNacDia), BirthdateMonth: parseInt(p.fechaNacMes), BirthdateYear: parseInt(p.fechaNacAnio),
        Email: p.email,
        DocumentType: p.docTipoId, DocumentCountry: p.docPaisId, DocumentNumber: p.docNumero,
        ExpirationdateDay: parseInt(p.docVencDia), ExpirationdateMonth: parseInt(p.docVencMes), ExpirationdateYear: parseInt(p.docVencAnio),
        Nationality: p.nacionalidadId,
        AccountingDocumentType: tipo!=='INF' ? p.factTipoId : null,
        AccountingDocumentCountry: tipo!=='INF' ? p.factPaisId : null,
        AccountingDocumentNumber: tipo!=='INF' ? p.factNumero : null,
        LoyaltyProgramAccounts: null,
        documentTypes: p.docTipos || [],
        accountingDocumentTypes: p.factTipos || []
      };
    }

    const adults = pasajeros.filter(p=>p.tipo==='ADT').map((p,i) => buildPax(p,i,'ADT'));
    const childs = pasajeros.filter(p=>p.tipo==='CHD').map((p,i) => buildPax(p,i,'CHD'));
    const infants = pasajeros.filter(p=>p.tipo==='INF').map((p,i) => buildPax(p,i,'INF'));

    // Parsear teléfono: puede venir como string "+54 911 1234-5678" o ya como objeto
    function parsePhone(tel) {
      if (!tel) return { Country: 'AR', DialCode: '+54', Number: null };
      if (typeof tel === 'object') return tel;
      const clean = tel.replace(/[\s\-]/g, '');
      return { Country: 'AR', DialCode: '+54', Number: clean.replace(/^\+54/, '') };
    }

    const bookPayload = {
      SearchId: searchId, QuotationId: String(quotationId), SelectedUpsellId: null,
      Adults: adults, Childs: childs, Infants: infants,
      Contact: {
        FirstName: contacto.nombre, LastName: contacto.apellido,
        Email: contacto.email,
        Phone1: parsePhone(contacto.telefono1),
        Phone2: parsePhone(contacto.telefono2)
      },
      PaymentType: null, Cash: null, CreditCard: null, BankTransfer: null,
      OnBehalfOfUserName: null
    };

    console.log('[Reserva] pasajeros recibidos:', JSON.stringify(pasajeros, null, 2));
    console.log('[Reserva] Payload:', JSON.stringify(bookPayload, null, 2));
    const r = await fetch(`${API_BASE}/FlightReservation/CreateReservationRemake`, {
      method:'POST', headers: getHeaders(token), body: JSON.stringify(bookPayload)
    });
    const rText = await r.text();
    if (!r.ok) {
      console.error('[Reserva] Error response:', rText.substring(0,500));
      throw new Error(`API ${r.status}: ${rText.substring(0,300)}`);
    }
    const rTextOk = rText;
    const data = JSON.parse(rTextOk);
    console.log('[Reserva] PNR:', data.recordLocator, 'Order:', data.orderNumber);

    // Guardar en DB
    if (db) {
      try {
        for (const p of pasajeros) {
          const ex = await db.query('SELECT id FROM clientes WHERE doc_numero=$1 AND doc_tipo=$2', [p.docNumero, p.docTipo]);
          if (ex.rows.length) {
            await db.query(`UPDATE clientes SET apellido=$1,nombre=$2,email=$3,genero=$4,
              fecha_nac_dia=$5,fecha_nac_mes=$6,fecha_nac_anio=$7,
              doc_pais=$8,doc_pais_id=$9,doc_tipo=$10,doc_tipo_id=$11,doc_numero=$12,
              doc_venc_dia=$13,doc_venc_mes=$14,doc_venc_anio=$15,
              nacionalidad=$16,nacionalidad_id=$17,
              fact_pais=$18,fact_pais_id=$19,fact_tipo=$20,fact_tipo_id=$21,fact_numero=$22,
              updated_at=NOW() WHERE id=$23`,
              [p.apellido,p.nombre,p.email,p.genero,
               p.fechaNacDia,p.fechaNacMes,p.fechaNacAnio,
               p.docPais,p.docPaisId,p.docTipo,p.docTipoId,p.docNumero,
               p.docVencDia,p.docVencMes,p.docVencAnio,
               p.nacionalidad,p.nacionalidadId,
               p.factPais,p.factPaisId,p.factTipo,p.factTipoId,p.factNumero,
               ex.rows[0].id]);
            p._clienteId = ex.rows[0].id;
          } else {
            const ins = await db.query(`INSERT INTO clientes (apellido,nombre,email,genero,
              fecha_nac_dia,fecha_nac_mes,fecha_nac_anio,
              doc_pais,doc_pais_id,doc_tipo,doc_tipo_id,doc_numero,
              doc_venc_dia,doc_venc_mes,doc_venc_anio,
              nacionalidad,nacionalidad_id,
              fact_pais,fact_pais_id,fact_tipo,fact_tipo_id,fact_numero)
              VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22)
              RETURNING id`,
              [p.apellido,p.nombre,p.email,p.genero,
               p.fechaNacDia,p.fechaNacMes,p.fechaNacAnio,
               p.docPais,p.docPaisId,p.docTipo,p.docTipoId,p.docNumero,
               p.docVencDia,p.docVencMes,p.docVencAnio,
               p.nacionalidad,p.nacionalidadId,
               p.factPais,p.factPaisId,p.factTipo,p.factTipoId,p.factNumero]);
            p._clienteId = ins.rows[0].id;
          }
        }

        const resIns = await db.query(`INSERT INTO reservas (
          pnr,order_id,order_number,source,search_id,quotation_id,
          tipo_viaje,origen,destino,fecha_salida,
          aerolinea,precio_usd,moneda,adultos,ninos,infantes,estado,
          itinerario_json,pasajeros_json,contacto_json)
          VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)
          RETURNING id`,
          [data.recordLocator, data.orderId, data.orderNumber, data.source,
           searchId, String(quotationId),
           vueloInfo?.tipo, vueloInfo?.origen, vueloInfo?.destino, vueloInfo?.salida,
           vueloInfo?.aerolinea, vueloInfo?.precioUSD, vueloInfo?.moneda,
           pasajeros.filter(p=>p.tipo==='ADT').length,
           pasajeros.filter(p=>p.tipo==='CHD').length,
           pasajeros.filter(p=>p.tipo==='INF').length,
           'CREADA',
           JSON.stringify(vueloInfo?.itinerario),
           JSON.stringify(pasajeros),
           JSON.stringify(contacto)]);

        for (const p of pasajeros) {
          if (p._clienteId) {
            await db.query('INSERT INTO reserva_pasajeros (reserva_id,cliente_id,tipo,apellido,nombre,email) VALUES ($1,$2,$3,$4,$5,$6)',
              [resIns.rows[0].id, p._clienteId, p.tipo, p.apellido, p.nombre, p.email]);
          }
        }
        console.log('[DB] Reserva guardada, PNR:', data.recordLocator);
      } catch(dbErr) {
        console.error('[DB] Error guardando:', dbErr.message);
      }
    }

    res.json({ ok:true, pnr: data.recordLocator, orderNumber: data.orderNumber, orderId: data.orderId });
  } catch(e) {
    console.error('[Reserva] Error:', e.message);
    res.json({ ok:false, error: e.message });
  }
});

// ─── CLIENTES ───
app.get('/clientes/buscar', async (req, res) => {
  if (!db) return res.json([]);
  const q = '%' + (req.query.q || '') + '%';
  try {
    const r = await db.query(
      'SELECT * FROM clientes WHERE apellido ILIKE $1 OR nombre ILIKE $2 OR doc_numero ILIKE $3 OR email ILIKE $4 ORDER BY updated_at DESC LIMIT 10',
      [q, q, q, q]
    );
    res.json(r.rows);
  } catch(e) { res.json([]); }
});

app.get('/clientes', async (req, res) => {
  if (!db) return res.json([]);
  try {
    const r = await db.query('SELECT * FROM clientes ORDER BY apellido, nombre LIMIT 100');
    res.json(r.rows);
  } catch(e) { res.json([]); }
});

// ─── RESERVAS GUARDADAS ───
app.get('/reservas', async (req, res) => {
  if (!db) return res.json([]);
  try {
    const { estado, q, limit } = req.query;
    let sql = 'SELECT * FROM reservas';
    const params = [];
    const where = [];
    if (estado && estado !== 'TODAS') {
      params.push(estado);
      where.push(`estado=$${params.length}`);
    }
    if (q) {
      params.push('%' + q + '%');
      const idx = params.length;
      where.push(`(pnr ILIKE $${idx} OR origen ILIKE $${idx} OR destino ILIKE $${idx} OR aerolinea ILIKE $${idx} OR order_number ILIKE $${idx})`);
    }
    if (where.length) sql += ' WHERE ' + where.join(' AND ');
    sql += ' ORDER BY created_at DESC LIMIT ' + (parseInt(limit) || 100);
    const r = await db.query(sql, params);
    res.json(r.rows);
  } catch(e) { console.error('[Reservas]', e.message); res.json([]); }
});

// Detalle de una reserva con pasajeros
app.get('/reservas/:id', async (req, res) => {
  if (!db) return res.json({ ok: false });
  try {
    const r = await db.query('SELECT * FROM reservas WHERE id=$1', [req.params.id]);
    if (!r.rows.length) return res.json({ ok: false, error: 'No encontrada' });
    const reserva = r.rows[0];
    const pax = await db.query(
      `SELECT rp.*, c.doc_numero, c.doc_tipo, c.fecha_nac_dia, c.fecha_nac_mes, c.fecha_nac_anio, c.genero
       FROM reserva_pasajeros rp LEFT JOIN clientes c ON rp.cliente_id=c.id WHERE rp.reserva_id=$1`,
      [req.params.id]
    );
    reserva.pasajeros_detalle = pax.rows;
    res.json({ ok: true, reserva });
  } catch(e) { res.json({ ok: false, error: e.message }); }
});

// Actualizar estado de reserva
app.put('/reservas/:id/estado', async (req, res) => {
  if (!db) return res.json({ ok: false });
  try {
    const { estado } = req.body;
    const estados = ['CREADA', 'EMITIDA', 'COMPLETADA', 'CANCELADA'];
    if (!estados.includes(estado)) return res.json({ ok: false, error: 'Estado inválido' });
    await db.query('UPDATE reservas SET estado=$1, updated_at=NOW() WHERE id=$2', [estado, req.params.id]);
    res.json({ ok: true });
  } catch(e) { res.json({ ok: false, error: e.message }); }
});

// Notas de reserva
app.put('/reservas/:id/notas', async (req, res) => {
  if (!db) return res.json({ ok: false });
  try {
    const { notas } = req.body;
    await db.query('UPDATE reservas SET notas=$1, updated_at=NOW() WHERE id=$2', [notas, req.params.id]);
    res.json({ ok: true });
  } catch(e) { res.json({ ok: false, error: e.message }); }
});

// ─── VERIFICAR ESTADO EN TIEMPO REAL (API Tucano) ───
app.post('/reservas/:id/verificar', async (req, res) => {
  if (!db) return res.json({ ok: false, error: 'Sin DB' });
  try {
    const r = await db.query('SELECT * FROM reservas WHERE id=$1', [req.params.id]);
    if (!r.rows.length) return res.json({ ok: false, error: 'Reserva no encontrada' });
    const reserva = r.rows[0];

    if (!reserva.order_id) return res.json({ ok: false, error: 'Sin orderId guardado' });

    const token = await getToken();
    const hdrs = getHeaders(token);

    // Endpoint real: POST FlightReservation/RetrieveReservation
    const resp = await fetch(`${API_BASE}/FlightReservation/RetrieveReservation`, {
      method: 'POST', headers: hdrs,
      body: JSON.stringify({ OrderId: reserva.order_id })
    });
    const text = await resp.text();
    console.log(`[Verificar] orderId=${reserva.order_id}, pnr=${reserva.pnr}, HTTP ${resp.status}`);
    console.log(`[Verificar] Response:`, text.substring(0, 500));
    if (!resp.ok) {
      return res.json({ ok: false, error: `API respondió ${resp.status}: ${text.substring(0, 200)}`, orderId: reserva.order_id });
    }

    let data;
    try { data = JSON.parse(text); } catch(e) {
      return res.json({ ok: false, error: 'Respuesta no-JSON' });
    }

    // Extraer información clave
    const pnr = data.recordLocator || reserva.pnr;
    const orderState = data.orderState; // numérico
    const timeLimit = data.limitDateTimeCTZ || data.lastTicketingDateCTZ || data.expiringDateTimeCTZ;

    // Tickets emitidos
    const tickets = (data.ticketsInformation || []).map(t => ({
      numero: t.number,
      carrier: t.validatigCarrierNumericCode,
      status: t.status // "E" = emitido
    }));
    const ticketsEmitidos = tickets.filter(t => t.status === 'E');

    // Estado de vuelos
    const vuelos = (data.flightsInformation || []).map(f => ({
      vuelo: f.flightNumber,
      ruta: `${f.departureAirportCode} → ${f.arrivalAirportCode}`,
      status: f.status // "OK", "XX" (cancelado), etc.
    }));
    const vuelosCancelados = vuelos.filter(v => v.status === 'XX' || v.status === 'UC' || v.status === 'UN');

    // Pasajeros con tickets
    const pasajeros = (data.passengersInformation || []).map(p => ({
      nombre: `${p.lastName}, ${p.firstName}`,
      tipo: p.typeCode,
      ticketStatus: p.tickets?.[0]?.status || null // "Emitido", "Reservado", etc.
    }));

    // Determinar estado
    let apiEstado = null;
    if (vuelosCancelados.length === vuelos.length && vuelos.length > 0) {
      apiEstado = 'CANCELADA';
    } else if (ticketsEmitidos.length > 0) {
      apiEstado = 'EMITIDA';
    } else if (vuelos.some(v => v.status === 'OK' || v.status === 'HK')) {
      apiEstado = 'CREADA'; // confirmada pero no emitida
    } else {
      apiEstado = 'CREADA';
    }

    // Actualizar en DB si cambió
    let estadoActualizado = false;
    if (apiEstado && apiEstado !== reserva.estado) {
      await db.query('UPDATE reservas SET estado=$1, updated_at=NOW() WHERE id=$2', [apiEstado, req.params.id]);
      estadoActualizado = true;
    }

    res.json({
      ok: true,
      estadoAPI: apiEstado,
      estadoAnterior: reserva.estado,
      estadoActualizado,
      pnr,
      orderState,
      timeLimit,
      tickets: ticketsEmitidos.map(t => `${t.carrier}-${t.numero}`),
      vuelos,
      pasajeros
    });
  } catch(e) {
    console.error('[Verificar] Error:', e.message);
    res.json({ ok: false, error: e.message });
  }
});

app.listen(PORT, () => console.log(`✅ Puerto ${PORT}`));

// ─── DETALLE DE VUELO (desglose de precio) ───
app.get('/detalle-vuelo', async (req, res) => {
  const { searchId, quotationId } = req.query;
  try {
    const token = await getToken();
    const r = await fetch(`${API_BASE}/FlightSearch/ItineraryDetailRemake?searchId=${searchId}&quotationId=${quotationId}`, {
      headers: getHeaders(token)
    });
    const text = await r.text();
    let data = {};
    try { data = JSON.parse(text); } catch(e) { 
      console.error('[Detalle] Respuesta no-JSON:', text.substring(0,300));
      throw new Error('Respuesta inválida: ' + text.substring(0,100)); 
    }
    
    const q = data.quote;
    if (!q) throw new Error('Sin datos de cotización');

    const amounts = q.amounts?.originalAmounts || {};
    const rates = q.flightRates || [];
    const penalties = q.penalties || [];

    // Desglose por pasajero
    const desglose = rates.map(r => ({
      tipo: r.passengerTypeCode,
      cantidad: r.passengerQuantity,
      tarifa: r.fareAmount,
      impuestos: r.taxAmount,
      fee: r.feeAmount,
      descuento: r.discountAmount || 0,
      total: r.sellingPriceAmount,
      detImpuestos: r.taxDetails || []
    }));

    // Penalidades
    const cambio = penalties.find(p => p.type === 0 && p.applicability === 0 && p.enabled);
    const cancelacion = penalties.find(p => p.type === 1 && p.applicability === 0 && p.enabled);

    res.json({
      ok: true,
      tarifa: amounts.fareAmount || 0,
      impuestos: amounts.taxAmount || 0,
      fee: amounts.feeAmount || 0,
      total: amounts.sellingPriceAmount || 0,
      moneda: amounts.fareCurrency || 'USD',
      desglose,
      penalidades: {
        cambio: cambio ? { monto: cambio.amount, moneda: cambio.currency } : null,
        cancelacion: cancelacion ? { monto: cancelacion.amount, moneda: cancelacion.currency } : null
      },
      reglas: q.rulesInformation?.filter(r => ['F','C'].includes(r.type)) || []
    });
  } catch(e) {
    console.error('[Detalle] Error:', e.message);
    res.json({ ok: false, error: e.message });
  }
});

// ─── CONFIGURACIÓN DE MARKUP ───
app.get('/config-markup', async (req, res) => {
  try {
    const r = await db.query('SELECT valor FROM config WHERE clave=$1', ['markup']);
    res.json({ markup: r.rows[0]?.valor ? JSON.parse(r.rows[0].valor) : { tipo: 'porcentaje', valor: 0 } });
  } catch(e) { res.json({ markup: { tipo: 'porcentaje', valor: 0 } }); }
});

app.post('/config-markup', async (req, res) => {
  const { markup } = req.body;
  try {
    await db.query(`INSERT INTO config (clave, valor) VALUES ($1, $2)
      ON CONFLICT (clave) DO UPDATE SET valor=$2`, ['markup', JSON.stringify(markup)]);
    res.json({ ok: true });
  } catch(e) { res.json({ ok: false, error: e.message }); }
});

// ─── COTIZACIÓN PDF ───
const PDFDocument = require('pdfkit');
const fsModule = require('fs');
const pathModule = require('path');

// ─── FUENTE UNICODE (DejaVu Sans soporta ✈ → ■) ───
// Primero buscar en el repo (bundled), luego en sistema
const FONT_PATHS = [
  { regular: pathModule.join(__dirname, 'fonts', 'DejaVuSans.ttf'),      bold: pathModule.join(__dirname, 'fonts', 'DejaVuSans-Bold.ttf') },
  { regular: '/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf',          bold: '/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf' },
];
let FONT_REGULAR = null, FONT_BOLD = null;
for (const p of FONT_PATHS) {
  if (fsModule.existsSync(p.regular) && fsModule.existsSync(p.bold)) {
    FONT_REGULAR = p.regular;
    FONT_BOLD = p.bold;
    break;
  }
}
const HAS_UNICODE_FONT = !!(FONT_REGULAR && FONT_BOLD);
console.log('[PDF] Fuente Unicode disponible:', HAS_UNICODE_FONT, FONT_REGULAR || '(ninguna)');

// Tablas de cálculo Lucky Tour
const FEE_TABLE = [
  [0, 599, 25], [600, 999, 30], [1000, 1499, 35],
  [1500, 1999, 40], [2000, 2999, 50], [3000, 3999, 55],
  [4000, 5499, 60], [5500, Infinity, 80]
];
const DESCUENTO_TABLE = [
  [0, 50, 0], [51, 80, 10], [81, 100, 20], [101, 140, 30],
  [141, 180, 40], [181, 220, 50], [221, 260, 60], [261, Infinity, 70]
];
const CONTACTOS = {
  guido:   { nombre: 'Guido Finkelstein',  mail: 'Guido@luckytourviajes.com',    tel: '+54 9 11 6846 3892' },
  julieta: { nombre: 'Julieta Zubeldia',   mail: 'Julietaz@luckytourviajes.com', tel: '+54 9 11 3295 5404' },
  ruthy:   { nombre: 'Ruthy Tuchsznajder', mail: 'Ventas@luckytourviajes.com',   tel: '+54 9 11 6847 0985' },
};

function getFee(neto) {
  for (const [low, high, fee] of FEE_TABLE) if (neto >= low && neto <= high) return fee;
  return 80;
}
function getDescuento(com) {
  for (const [low, high, desc] of DESCUENTO_TABLE) if (com >= low && com <= high) return desc;
  return 70;
}
function redondearArriba(p) { return Math.ceil(p / 5) * 5; }
function redondearAbajo(p)  { return Math.floor(p / 5) * 5; }
function calcularPrecio(neto, tipoTarifa, comOver) {
  if (tipoTarifa === 'PNEG' || comOver <= 50) return redondearArriba(neto + getFee(neto));
  return redondearAbajo(neto - getDescuento(comOver));
}
function etiquetaPrecio(precio, tipo, cantidad, totalPax, multiTipos) {
  if (totalPax === 1) return `USD ${precio.toLocaleString('en')}`;
  if (!multiTipos) return `USD ${precio.toLocaleString('en')} cada ${tipo}`;
  return cantidad > 1 ? `USD ${precio.toLocaleString('en')} cada ${tipo}` : `USD ${precio.toLocaleString('en')} ${tipo}`;
}

function generarPDFBuffer(opciones, vendedor, nombreCliente) {
  return new Promise((resolve, reject) => {
    const NAVY = '#1B3A5C';
    const contacto = CONTACTOS[vendedor] || CONTACTOS.guido;
    // Buscar logo en public/ y raíz
    const logoCandidates = [
      pathModule.join(__dirname, 'public', 'logo_transparent.png'),
      pathModule.join(__dirname, 'logo_transparent.png'),
    ];
    const logoFinal = logoCandidates.find(p => fsModule.existsSync(p)) || null;

    const doc = new PDFDocument({ size: 'A4', margin: 40, bufferPages: true });
    const chunks = [];
    doc.on('data', c => chunks.push(c));
    doc.on('end', () => resolve(Buffer.concat(chunks)));
    doc.on('error', reject);

    // Registrar fuentes Unicode si están disponibles
    const BOLD = HAS_UNICODE_FONT ? 'UCBold' : 'Helvetica-Bold';
    const REGULAR = HAS_UNICODE_FONT ? 'UCRegular' : 'Helvetica';
    if (HAS_UNICODE_FONT) {
      doc.registerFont('UCRegular', FONT_REGULAR);
      doc.registerFont('UCBold', FONT_BOLD);
    }

    // Símbolos Unicode o fallback ASCII
    const SYM_PLANE  = HAS_UNICODE_FONT ? '\u2708' : '>>';
    const SYM_ARROW  = HAS_UNICODE_FONT ? ' \u2192 ' : ' > ';
    const SYM_SQUARE = HAS_UNICODE_FONT ? '\u25A0' : '#';
    const SYM_DOT    = HAS_UNICODE_FONT ? ' \u00B7 ' : ' \u00B7 ';

    const esMultiple = opciones.length > 1;
    const W = 515; // ancho útil
    const PAGE_LEFT = 40;

    function dibujarCabecera() {
      // Fecha arriba a la derecha
      doc.fontSize(9).fillColor('#666666').font(REGULAR)
         .text(new Date().toLocaleDateString('es-AR'), PAGE_LEFT, 40, { width: W, align: 'right' });

      // Logo centrado y grande
      if (logoFinal) {
        const logoW = 200;  // Grande como en el PDF de referencia
        const logoX = PAGE_LEFT + (W - logoW) / 2;
        doc.image(logoFinal, logoX, 55, { width: logoW });
        doc.y = 220;  // Saltar después del logo grande
      } else {
        doc.y = 80;
      }

      // Título "Cotización" grande, centrado
      doc.fontSize(22).fillColor(NAVY).font(BOLD)
         .text('Cotizaci\u00f3n', PAGE_LEFT, doc.y, { width: W, align: 'center' });

      // Nombre del cliente debajo (si existe)
      if (nombreCliente) {
        doc.moveDown(0.1);
        doc.fontSize(11).fillColor('#444444').font(REGULAR)
           .text(nombreCliente, PAGE_LEFT, doc.y, { width: W, align: 'center' });
      }

      doc.moveDown(0.4);

      // Línea separadora navy gruesa
      const lineY = doc.y;
      doc.moveTo(PAGE_LEFT, lineY).lineTo(PAGE_LEFT + W, lineY)
         .lineWidth(2).strokeColor(NAVY).stroke();
      doc.y = lineY + 14;
    }

    function dibujarFooter() {
      // No hacer nada aquí - el footer se dibuja en dibujarFooterEnPagina()
    }

    function dibujarFooterEnPagina() {
      // Guardar posición actual del cursor
      const savedY = doc.y;
      const pageH = doc.page.height;
      const y = pageH - 70;

      // Línea navy
      doc.moveTo(PAGE_LEFT, y).lineTo(PAGE_LEFT + W, y)
         .lineWidth(1.5).strokeColor(NAVY).stroke();

      // "Contacto:   Nombre" en bold navy
      doc.fontSize(9).font(BOLD).fillColor(NAVY);
      doc.text('Contacto:    ' + contacto.nombre, PAGE_LEFT, y + 8, { lineBreak: false });

      // Mail
      doc.fontSize(9).font(REGULAR).fillColor('#333333');
      doc.text(contacto.mail, PAGE_LEFT, y + 22, { lineBreak: false });

      // Teléfono
      doc.text(contacto.tel, PAGE_LEFT, y + 34, { lineBreak: false });

      // Restaurar posición del cursor
      doc.y = savedY;
    }

    dibujarCabecera();

    for (let i = 0; i < opciones.length; i++) {
      if (i > 0) {
        doc.addPage();
        dibujarCabecera();
      }
      const op = opciones[i];

      // Badge OPCIÓN N (solo si hay múltiples opciones)
      if (esMultiple) {
        const badgeY = doc.y;
        doc.rect(PAGE_LEFT, badgeY, W, 22).fill(NAVY);
        doc.fontSize(10).font(BOLD).fillColor('white')
           .text(`  OPCI\u00d3N ${i + 1}`, PAGE_LEFT + 6, badgeY + 5, { lineBreak: false });
        doc.y = badgeY + 30;
      }

      // ── ITINERARIO ──
      const tituloItin = op.aerolinea
        ? `${SYM_PLANE}  ITINERARIO - ${op.aerolinea}`
        : `${SYM_PLANE}  ITINERARIO`;
      doc.fontSize(9).font(BOLD).fillColor(NAVY).text(tituloItin, PAGE_LEFT, doc.y);
      doc.moveDown(0.5);

      for (const v of op.vuelos) {
        // Línea principal: fecha  origen → destino   salida → llegada
        const lineaVuelo = `${v.fecha}   ${v.origen}${SYM_ARROW}${v.destino}   ${v.salida}${SYM_ARROW}${v.llegada}`;
        doc.fontSize(10).font(BOLD).fillColor('#000000').text(lineaVuelo, PAGE_LEFT);

        // Detalle bajo cada vuelo: "AA 0900 · Basic Economy"
        if (v.numero_vuelo) {
          const detalleLine = v.brand
            ? `${v.numero_vuelo}${SYM_DOT}${v.brand}`
            : v.numero_vuelo;
          doc.fontSize(8).font(REGULAR).fillColor('#555555').text(detalleLine, PAGE_LEFT);
        }
        doc.moveDown(0.3);
      }

      // Clase general (sin brand, ya se muestra en cada vuelo)
      const cabinaOnly = (op.detalle_vuelo || '').split(' - ')[0].trim() || op.detalle_vuelo;
      doc.fontSize(8).font(REGULAR).fillColor('#555555').text(cabinaOnly, PAGE_LEFT);
      doc.moveDown(0.8);

      // ── PRECIOS ──
      const totalPax = op.pasajeros.reduce((s, p) => s + p.cantidad, 0);
      const multiTipos = op.pasajeros.length > 1;
      const tituloPrecios = totalPax === 1
        ? `${SYM_SQUARE} PRECIO`
        : `${SYM_SQUARE} PRECIOS`;
      doc.fontSize(9).font(BOLD).fillColor(NAVY).text(tituloPrecios, PAGE_LEFT);
      doc.moveDown(0.4);

      for (const pax of op.pasajeros) {
        const precio = calcularPrecio(pax.neto, pax.tipo_tarifa, pax.comision_over);
        const linea = etiquetaPrecio(precio, pax.tipo, pax.cantidad, totalPax, multiTipos);
        doc.fontSize(11).font(BOLD).fillColor(NAVY).text(linea, PAGE_LEFT);
        doc.moveDown(0.3);
      }
    }

    doc.flushPages();
    dibujarFooter();
    doc.end();
  });
}

app.post('/generar-cotizacion', async (req, res) => {
  const { opciones, vendedor, nombreCliente } = req.body;
  try {
    const token = await getToken();

    const opcionesCompletas = await Promise.all(opciones.map(async (op) => {
      const r = await fetch(`${API_BASE}/FlightSearch/ItineraryDetailRemake?searchId=${op.searchId}&quotationId=${op.quotationId}`, {
        headers: getHeaders(token)
      });
      const text = await r.text();
      let d;
      try { d = JSON.parse(text); } catch(e) { throw new Error('Error al obtener detalle'); }

      const q = d.quote;
      const rates = q.flightRates || [];

      const pasajeros = rates.map(rate => {
        const neto = rate.sellingPriceAmount;
        const comOver = (rate.commissionRule?.ceded?.valueApplied || 0) + (rate.overCommissionRule?.ceded?.valueApplied || 0);
        const code = rate.passengerTypeCode;
        const codeStr = String(code || '').toUpperCase();
        const paxType = rate.passengerType; // some APIs use numeric passengerType

        let tipoLabel;
        if (codeStr === 'ADT' || codeStr === 'AD' || paxType === 0 || codeStr === '0') {
          tipoLabel = 'adulto';
        } else if (codeStr === 'CHD' || codeStr === 'CNN' || codeStr === 'CH' || codeStr === 'CLD' || codeStr === 'CHILD' || paxType === 1 || codeStr === '1') {
          tipoLabel = 'menor';
        } else if (codeStr === 'INF' || codeStr === 'INS' || paxType === 2 || codeStr === '2') {
          tipoLabel = 'beb\u00e9';
        } else {
          // Fallback: si no reconocemos el código, inferir por precio
          tipoLabel = neto > 200 ? 'menor' : 'beb\u00e9';
        }
        console.log(`[Cotizacion] Pasajero: typeCode=${code} passengerType=${paxType} => ${tipoLabel} neto=${neto} cant=${rate.passengerQuantity}`);
        return { tipo: tipoLabel, cantidad: rate.passengerQuantity, neto, tipo_tarifa: rate.fareType || 'PUB', comision_over: comOver };
      });

      const trip = q.trip || [];
      const vuelos = [];
      const cabinMap = { 0: 'Primera', 1: 'Economica', 2: 'Business', 3: 'Premium Economy' };

      // Mapeo de aeropuertos comunes a ciudades (fallback cuando la API no da city name)
      const AIRPORT_CITY = {
        'EZE':'Buenos Aires','AEP':'Buenos Aires','MIA':'Miami','MAD':'Madrid','BCN':'Barcelona',
        'FCO':'Roma','CDG':'Paris','ORY':'Paris','LHR':'Londres','LGW':'Londres','FRA':'Frankfurt',
        'AMS':'Amsterdam','IST':'Estambul','SAW':'Estambul','DXB':'Dubai','DOH':'Doha',
        'TLV':'Tel Aviv','ADD':'Addis Abeba','GRU':'San Pablo','GIG':'Rio de Janeiro',
        'SCL':'Santiago','LIM':'Lima','BOG':'Bogota','PTY':'Panama','CUN':'Cancun',
        'MEX':'Mexico DF','JFK':'Nueva York','EWR':'Nueva York','LAX':'Los Angeles',
        'ORD':'Chicago','ATL':'Atlanta','DFW':'Dallas','CLT':'Charlotte','PHL':'Filadelfia',
        'MVD':'Montevideo','ASU':'Asuncion','COR':'Cordoba','MDZ':'Mendoza','BRC':'Bariloche',
        'IGR':'Iguazu','FTE':'El Calafate','USH':'Ushuaia','NQN':'Neuquen','ROS':'Rosario',
        'SLA':'Salta','TUC':'Tucuman','JUJ':'Jujuy','PMC':'Puerto Montt','PUQ':'Punta Arenas',
        'SSA':'Salvador','REC':'Recife','FOR':'Fortaleza','FLN':'Florianopolis',
        'SDU':'Rio de Janeiro','CNF':'Belo Horizonte','CWB':'Curitiba','POA':'Porto Alegre',
        'VCP':'Campinas','BSB':'Brasilia','MXP':'Milan','LIN':'Milan','MUC':'Munich',
        'ZRH':'Zurich','VIE':'Viena','CPH':'Copenhague','OSL':'Oslo','ARN':'Estocolmo',
        'HEL':'Helsinki','WAW':'Varsovia','PRG':'Praga','BUD':'Budapest','OTP':'Bucarest',
        'ATH':'Atenas','LIS':'Lisboa','OPO':'Oporto','DUB':'Dublin','EDI':'Edimburgo',
        'BRU':'Bruselas','GVA':'Ginebra','NCE':'Niza','MRS':'Marsella','LYS':'Lyon',
        'NRT':'Tokio','HND':'Tokio','ICN':'Seul','PEK':'Beijing','PVG':'Shanghai',
        'HKG':'Hong Kong','SIN':'Singapur','BKK':'Bangkok','DEL':'Delhi','BOM':'Mumbai',
        'SYD':'Sydney','MEL':'Melbourne','AKL':'Auckland','JNB':'Johannesburgo',
        'CAI':'El Cairo','CMN':'Casablanca','NBO':'Nairobi','CPT':'Ciudad del Cabo',
      };

      function cityFromCode(code) {
        return AIRPORT_CITY[code] || '';
      }

      for (const tramo of trip) {
        const flights = tramo.legFlights || [];
        for (let fi = 0; fi < flights.length; fi++) {
          const flight = flights[fi];
          const dep = new Date(flight.departure || tramo.departure);
          const arr = new Date(flight.arrival || tramo.arrival);

          let origenNombre, origenCode, destinoNombre, destinoCode;

          if (flights.length === 1) {
            // Vuelo directo
            origenNombre = tramo.cityNameFrom;
            origenCode = tramo.airportCodeFrom;
            destinoNombre = tramo.cityNameTo;
            destinoCode = tramo.airportCodeTo;
          } else {
            // Con escalas: encadenar segmentos
            // Primer segmento: origen = tramo.from, destino = flight.arrival
            // Último segmento: origen = flight.departure, destino = tramo.to
            // Intermedios: ambos del flight
            const depCode = flight.departureAirportCode || flight.departureAirport || flight.airportCodeFrom || '';
            const arrCode = flight.arrivalAirportCode || flight.arrivalAirport || flight.airportCodeTo || '';

            if (fi === 0) {
              origenNombre = tramo.cityNameFrom;
              origenCode = tramo.airportCodeFrom;
              destinoNombre = flight.arrivalCityName || flight.arrivalCity || cityFromCode(arrCode);
              destinoCode = arrCode;
            } else if (fi === flights.length - 1) {
              origenNombre = flight.departureCityName || flight.departureCity || cityFromCode(depCode);
              origenCode = depCode;
              destinoNombre = tramo.cityNameTo;
              destinoCode = tramo.airportCodeTo;
            } else {
              origenNombre = flight.departureCityName || flight.departureCity || cityFromCode(depCode);
              origenCode = depCode;
              destinoNombre = flight.arrivalCityName || flight.arrivalCity || cityFromCode(arrCode);
              destinoCode = arrCode;
            }
          }

          // Formatear: "Buenos Aires (EZE)" o solo "(MAD)" si no hay nombre
          const origenStr = origenNombre ? `${origenNombre} (${origenCode})` : `(${origenCode})`;
          const destinoStr = destinoNombre ? `${destinoNombre} (${destinoCode})` : `(${destinoCode})`;

          vuelos.push({
            fecha: `${String(dep.getDate()).padStart(2,'0')}/${String(dep.getMonth()+1).padStart(2,'0')}`,
            origen: origenStr,
            destino: destinoStr,
            salida: `${String(dep.getHours()).padStart(2,'0')}.${String(dep.getMinutes()).padStart(2,'0')}`,
            llegada: `${String(arr.getHours()).padStart(2,'0')}.${String(arr.getMinutes()).padStart(2,'0')}`,
            numero_vuelo: `${flight.airlineCode} ${flight.flightNumber}`,
            brand: flight.brandName || ''
          });
        }
      }

      const cabin = cabinMap[trip[0]?.legFlights?.[0]?.cabinType] || 'Economica';
      const brand = trip[0]?.legFlights?.[0]?.brandName || '';
      const detalle = brand ? `${cabin} - ${brand}` : cabin;

      return {
        aerolinea: d.airlinesDictionary?.[q.validatingCarrier] || q.validatingCarrier,
        vuelos, detalle_vuelo: detalle, pasajeros
      };
    }));

    const pdfBuffer = await generarPDFBuffer(opcionesCompletas, vendedor || 'guido', nombreCliente || '');
    console.log('[Cotizacion] Opciones:', JSON.stringify(opcionesCompletas.map(o => ({
      aerolinea: o.aerolinea,
      vuelos: o.vuelos.length,
      pasajeros: o.pasajeros.map(p => `${p.cantidad}x ${p.tipo} neto=${p.neto}`)
    }))));
    res.set({ 'Content-Type': 'application/pdf', 'Content-Disposition': 'attachment; filename="cotizacion_lucky_tour.pdf"' });
    res.send(pdfBuffer);
  } catch(e) {
    console.error('[Cotizacion] Error:', e.message);
    res.status(500).json({ ok: false, error: e.message });
  }
});

const express = require('express');
const path = require('path');
const app = express();
app.use(express.json());
app.use(express.static('public'));

const PORT = process.env.PORT || 3000;
const SCIWEB_USER = process.env.SCIWEB_USER;
const SCIWEB_PASS = process.env.SCIWEB_PASS;
const API_BASE = 'https://api-gwc.glas.travel/api';
const COMPANY_ID = '3036';
const WHOLESALER_ID = '538';

// DB
const db = require('./db');

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
    const r = await db.query('SELECT * FROM reservas ORDER BY created_at DESC LIMIT 50');
    res.json(r.rows);
  } catch(e) { res.json([]); }
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

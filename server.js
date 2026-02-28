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

let tokenCache = { token: null, expiry: 0 };

async function getToken() {
  if (tokenCache.token && Date.now() < tokenCache.expiry) return tokenCache.token;
  console.log('[Auth] Obteniendo token...');
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
  console.log('[Auth] Token OK');
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

app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
// Tipo de cambio BSP (Jazz Operador)
let tcCache = { bsp: null, expiry: 0 };
app.get('/tipo-cambio', async (req, res) => {
  try {
    if (tcCache.bsp && Date.now() < tcCache.expiry) return res.json({ bsp: tcCache.bsp });
    const r = await fetch('https://jazzoperador.tur.ar/cotizacion-historica/');
    const html = await r.text();
    // Parsear la tabla: buscar la primera fila con valor BSP válido
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
    if (!bsp) bsp = 1425; // fallback
    tcCache = { bsp, expiry: Date.now() + 60 * 60 * 1000 }; // cache 1 hora
    console.log('[BSP] Tipo de cambio BSP:', bsp);
    res.json({ bsp });
  } catch(e) {
    console.error('[BSP] Error:', e.message);
    res.json({ bsp: tcCache.bsp || 1425 });
  }
});

app.get('/health', (req, res) => res.json({ ok:true, configured:!!(SCIWEB_USER && SCIWEB_PASS) }));

app.post('/buscar-vuelos', async (req, res) => {
  const { tipo, origen, destino, salida, regreso, adultos, ninos, infantes, stops, tramos, moneda } = req.body;
  console.log(`[Vuelos] tipo=${tipo} ${origen||'multi'}→${destino||''}`);
  try {
    const token = await getToken();

    let payload, endpoint, addSearchPayload;
    const stopsVal = null; // Siempre null, filtramos del lado nuestro
    const stopsFilter = (stops !== undefined && stops !== '') ? parseInt(stops) : null;
    const currencyCode = moneda === 'ARS' ? null : 'USD';

    if (tipo === 'oneway') {
      // ONE WAY - usa MultipleLegs con un solo tramo
      endpoint = `${API_BASE}/FlightSearch/OnewayRemake`;
      payload = {
        DepartCode: origen, ArrivalCode: destino,
        DepartDate: `${salida}T00:00:00`, DepartTime: null,
        Adults: parseInt(adultos), Childs: parseInt(ninos), Infants: parseInt(infantes),
        CabinType: null, Stops: stopsVal, Airlines: [],
        TypeOfFlightAllowedInItinerary: null, SortByGLASAlgorithm: "",
        AlternateCurrencyCode: currencyCode, CorporationCodeGlas: null, IncludeFiltersOptions: true
      };
      addSearchPayload = { SearchTravelType: 2, OneWayModel: payload, MultipleLegsModel: null, RoundTripModel: null };

    } else if (tipo === 'roundtrip') {
      // ROUND TRIP
      endpoint = `${API_BASE}/FlightSearch/RoundTripRemake`;
      payload = {
        DepartCode: origen, ArrivalCode: destino,
        DepartDate: `${salida}T00:00:00`, ArrivalDate: `${regreso}T00:00:00`,
        ArrivalTime: null, DepartTime: null,
        Adults: parseInt(adultos), Childs: parseInt(ninos), Infants: parseInt(infantes),
        CabinType: null, Stops: stopsVal, Airlines: [],
        TypeOfFlightAllowedInItinerary: null, SortByGLASAlgorithm: "",
        AlternateCurrencyCode: currencyCode, CorporationCodeGlas: null, IncludeFiltersOptions: true
      };
      addSearchPayload = { SearchTravelType: 1, OneWayModel: null, MultipleLegsModel: null, RoundTripModel: payload };

    } else if (tipo === 'multidestino') {
      // MULTIDESTINO
      endpoint = `${API_BASE}/FlightSearch/OnewayRemake`;
      const legs = tramos.map((t, i) => ({
        LegNumber: i + 1,
        DepartCode: t.origen,
        ArrivalCode: t.destino,
        DepartDate: `${t.salida}T00:00:00`,
        DepartTime: null,
        CabinType: null,
        Stops: stopsVal,
        Airlines: []
      }));
      payload = {
        Legs: legs,
        Adults: parseInt(adultos), Childs: parseInt(ninos), Infants: parseInt(infantes),
        TypeOfFlightAllowedInItinerary: null, SortByGLASAlgorithm: "",
        AlternateCurrencyCode: currencyCode, CorporationCodeGlas: null, IncludeFiltersOptions: true
      };
      addSearchPayload = { SearchTravelType: 3, OneWayModel: null, MultipleLegsModel: payload, RoundTripModel: null };
    }

    // AddSearch (historial)
    await fetch(`${API_BASE}/FlightSearchHistory/AddSearch`, {
      method: 'POST', headers: getHeaders(token), body: JSON.stringify(addSearchPayload)
    }).catch(() => {});

    // Búsqueda
    const searchRes = await fetch(endpoint, {
      method: 'POST', headers: getHeaders(token), body: JSON.stringify(payload)
    });

    if (!searchRes.ok) {
      const errText = await searchRes.text();
      throw new Error(`API error: ${searchRes.status} - ${errText.substring(0, 300)}`);
    }

    const data = await searchRes.json();
    console.log(`[Vuelos] ${data.minifiedQuotations?.length || 0} resultados`)

;

    const vuelos = procesarVuelos(data, stopsFilter);
    res.json({ ok:true, vuelos, total: data.minifiedQuotations?.length || 0 });

  } catch (err) {
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
        return {
          legId,
          origen: leg.originAirportCode,
          destino: leg.destinationAirportCode,
          salida: leg.departure,
          llegada: leg.arrival,
          duracionMin: leg.elapsedFlightTimeInMinutes,
          duracion: leg.elapsedFlightTimeInMinutesFormatted,
          escalas: (() => {
            const c = leg.connectingCityCodesList;
            if (!c) return 0;
            if (Array.isArray(c)) return c.length;
            if (typeof c === 'string') return c.split(',').filter(Boolean).length;
            return 0;
          })(),
          ciudadesEscala: (() => {
            const c = leg.connectingCityCodesList;
            if (!c) return [];
            if (Array.isArray(c)) return c;
            if (typeof c === 'string') return c.split(',').filter(Boolean);
            return [];
          })(),
          tripDays: leg.tripDays || 0,
        };
      }).filter(Boolean);

      const bagLeg = q.legsWithBaggageAllowance?.[0]?.baggageAllowance;
      const maxEscalas = itinerario.length > 0 ? itinerario.reduce((max, l) => Math.max(max, l.escalas || 0), 0) : 0;

      // Mochila (handOn)
      const handOnList = bagLeg?.handOn || [];
      const handOnIncluido = handOnList.some(b => b.chargeType === 0 && b.pieces > 0);
      const handOnLabel = handOnList.length > 0 ? (handOnIncluido ? 'Incluida' : 'Con cargo') : 'No informado';

      // Carry on (carryOn)
      const carryOnList = bagLeg?.carryOn || [];
      const carryOnItem = carryOnList.find(b => b.chargeType === 0 && b.pieces > 0);
      const carryOnIncluido = !!carryOnItem;
      const carryOnLabel = carryOnItem
        ? (`${carryOnItem.weight || ''}${carryOnItem.weightUnit || ''}`).trim() || 'Incluido'
        : (carryOnList.length > 0 ? 'Con cargo' : 'No incluido');

      // Maleta despachada (checked) - solo adultos
      const checkedList = (bagLeg?.checked || []).filter(b => b.passengerType === 0);
      const checkedIncluido = checkedList.some(b => b.chargeType === 0 && (b.pieces > 0 || (b.weight && b.weight !== '0')));
      const checkedItem = checkedList.find(b => b.chargeType === 0 && (b.pieces > 0 || (b.weight && b.weight !== '0')));
      const checkedLabel = checkedItem
        ? (checkedItem.pieces > 0 ? `${checkedItem.pieces}x ${checkedItem.weight}${checkedItem.unit}` : `${checkedItem.weight}${checkedItem.unit}`)
        : 'No incluida';

      const precioUSD = q.grandTotalSellingPriceAmount || 0;

      return {
        id: q.quotationId,
        aerolinea: q.validatingCarrier,
        aerolineaDesc: airlinesMap[q.validatingCarrier] || q.sourceDescription || q.source,
        precioUSD,
        expira: q.offerExpirationTimeCTZ,
        itinerario,
        escalas: maxEscalas,
        equipaje: {
          handOn: { label: handOnLabel, incluido: handOnIncluido },
          carryOn: { label: carryOnLabel, incluido: carryOnIncluido },
          checked: { label: checkedLabel, incluido: checkedIncluido }
        },
        source: q.source
      };
    })
    .filter(v => stopsFilter === null || v.escalas <= stopsFilter)
    .sort((a, b) => a.precio - b.precio);
}

app.listen(PORT, () => console.log(`✅ Servidor en puerto ${PORT}`));

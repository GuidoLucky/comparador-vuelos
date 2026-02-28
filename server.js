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
app.get('/health', (req, res) => res.json({ ok:true, configured:!!(SCIWEB_USER && SCIWEB_PASS) }));

app.post('/buscar-vuelos', async (req, res) => {
  const { tipo, origen, destino, salida, regreso, adultos, ninos, infantes, stops, tramos } = req.body;
  console.log(`[Vuelos] tipo=${tipo} ${origen||'multi'}→${destino||''}`);
  try {
    const token = await getToken();

    let payload, endpoint, addSearchPayload;
    const stopsVal = null; // Siempre null, filtramos del lado nuestro
    const stopsFilter = (stops !== undefined && stops !== '') ? parseInt(stops) : null;

    if (tipo === 'oneway') {
      // ONE WAY - usa MultipleLegs con un solo tramo
      endpoint = `${API_BASE}/FlightSearch/OnewayRemake`;
      payload = {
        DepartCode: origen, ArrivalCode: destino,
        DepartDate: `${salida}T00:00:00`, DepartTime: null,
        Adults: parseInt(adultos), Childs: parseInt(ninos), Infants: parseInt(infantes),
        CabinType: null, Stops: stopsVal, Airlines: [],
        TypeOfFlightAllowedInItinerary: null, SortByGLASAlgorithm: null,
        AlternateCurrencyCode: 'USD', CorporationCodeGlas: null, IncludeFiltersOptions: true
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
        TypeOfFlightAllowedInItinerary: null, SortByGLASAlgorithm: null,
        AlternateCurrencyCode: 'USD', CorporationCodeGlas: null, IncludeFiltersOptions: true
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
        TypeOfFlightAllowedInItinerary: null, SortByGLASAlgorithm: null,
        AlternateCurrencyCode: 'USD', CorporationCodeGlas: null, IncludeFiltersOptions: true
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
    // Debug: ver estructura de legs para entender escalas
    const legsDebug = data.minifiedLegs || {};
    const firstKeys = Object.keys(legsDebug).slice(0,3);
    firstKeys.forEach(k => {
      const l = legsDebug[k];
      console.log(`[Leg ${k}] connecting=${JSON.stringify(l.connectingCityCodesList)} hasTech=${l.hasTechnicalStops} typeOfFlight=${l.typeOfFlight}`);
    });;

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

      const equipaje = q.legsWithBaggageAllowance?.[0]?.baggageAllowance;
      const checkedBag = equipaje?.checked?.[0];
      const carryOn = equipaje?.carryOn?.[0];
      const maxEscalas = itinerario.length > 0 ? itinerario.reduce((max, l) => Math.max(max, l.escalas || 0), 0) : 0;

      // Maleta despachada
      let maletaLabel = 'Sin maleta';
      let maletaIncluida = false;
      if (checkedBag) {
        const w = checkedBag.weight;
        const p = checkedBag.pieces;
        if (p > 0) { maletaLabel = `${p}x maleta`; maletaIncluida = true; }
        else if (w && w !== '0') { maletaLabel = `${w}${checkedBag.unit || 'KG'}`; maletaIncluida = checkedBag.chargeType === 0; }
      }

      return {
        id: q.quotationId,
        aerolinea: q.validatingCarrier,
        aerolineaDesc: airlinesMap[q.validatingCarrier] || q.sourceDescription || q.source,
        precio: q.grandTotalSellingPriceAmount,
        moneda: q.grandTotalSellingPriceCurrency || 'USD',
        expira: q.offerExpirationTimeCTZ,
        itinerario,
        escalas: maxEscalas,
        maleta: maletaLabel,
        maletaIncluida,
        handBag: carryOn?.pieces > 0 ? 'Incluido' : 'No incluido',
        source: q.source
      };
    })
    .filter(v => stopsFilter === null || v.escalas <= stopsFilter)
    .sort((a, b) => a.precio - b.precio);
}

app.listen(PORT, () => console.log(`✅ Servidor en puerto ${PORT}`));

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
  const body = new URLSearchParams({
    mode: 'pass',
    username: SCIWEB_USER,
    password: SCIWEB_PASS,
    channel: 'GWC',
    defaultWholesalerId: WHOLESALER_ID
  });
  const res = await fetch(`${API_BASE}/Account/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Origin': 'https://sciweb.tucanotours.com.ar', 'Referer': 'https://sciweb.tucanotours.com.ar/' },
    body: body.toString()
  });
  const data = await res.json();
  const token = data.access_token || data.token || data.Token || data.AccessToken;
  if (!token) throw new Error('No se pudo obtener token: ' + JSON.stringify(data));
  tokenCache = { token, expiry: Date.now() + 50 * 60 * 1000 };
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
app.get('/debug-search', async (req, res) => {
  try {
    const token = await getToken();
    const payload = {
      DepartCode: 'BUE', ArrivalCode: 'MIA',
      DepartDate: '2026-03-28T00:00:00', ArrivalDate: '2026-04-04T00:00:00',
      ArrivalTime: null, DepartTime: null,
      Adults: 2, Childs: 0, Infants: 0,
      CabinType: null, Stops: null, Airlines: [],
      TypeOfFlightAllowedInItinerary: 3, SortByGLASAlgorithm: null,
      AlternateCurrencyCode: 'USD', CorporationCodeGlas: null, IncludeFiltersOptions: true
    };
    const searchRes = await fetch(`${API_BASE}/FlightSearch/RoundTripRemake`, {
      method: 'POST', headers: getHeaders(token), body: JSON.stringify(payload)
    });
    const data = await searchRes.json();
    // Devolver estructura sin minifiedQuotations para ver legs y flights
    res.json({
      keys: Object.keys(data),
      legsCount: data.legs?.length,
      flightsCount: data.flights?.length,
      quotationsCount: data.minifiedQuotations?.length,
      firstLeg: data.legs?.[0],
      firstFlight: data.flights?.[0],
      firstQuotation: data.minifiedQuotations?.[0]
    });
  } catch(e) { res.json({ error: e.message }); }
});

app.get('/health', (req, res) => res.json({ ok: true, configured: !!(SCIWEB_USER && SCIWEB_PASS) }));

app.post('/buscar-vuelos', async (req, res) => {
  const { origen, destino, salida, regreso, adultos, ninos, infantes } = req.body;
  console.log(`[Vuelos] ${origen}→${destino} | ${salida}-${regreso} | ${adultos}A ${ninos}N ${infantes}I`);
  try {
    const token = await getToken();
    const payload = {
      SearchTravelType: 1,
      OneWayModel: null,
      MultipleLegsModel: null,
      RoundTripModel: {
        DepartCode: origen, ArrivalCode: destino,
        DepartDate: `${salida}T00:00:00`, ArrivalDate: `${regreso}T00:00:00`,
        ArrivalTime: null, DepartTime: null,
        Adults: parseInt(adultos), Childs: parseInt(ninos), Infants: parseInt(infantes),
        CabinType: null, Stops: null, Airlines: [],
        TypeOfFlightAllowedInItinerary: 3, SortByGLASAlgorithm: null,
        AlternateCurrencyCode: 'USD', CorporationCodeGlas: null, IncludeFiltersOptions: true
      }
    };

    // Paso 1: AddSearch - guarda el historial y devuelve searchId
    const addRes = await fetch(`${API_BASE}/FlightSearchHistory/AddSearch`, {
      method: 'POST', headers: getHeaders(token), body: JSON.stringify(payload)
    });
    console.log('[Vuelos] AddSearch status:', addRes.status);

    // Paso 2: RoundTripRemake con el mismo payload
    // RoundTripRemake recibe solo el RoundTripModel, no el wrapper
    const searchRes = await fetch(`${API_BASE}/FlightSearch/RoundTripRemake`, {
      method: 'POST', headers: getHeaders(token), body: JSON.stringify(payload.RoundTripModel)
    });

    if (!searchRes.ok) {
      const errText = await searchRes.text();
      throw new Error(`API error: ${searchRes.status} - ${errText.substring(0, 300)}`);
    }
    const data = await searchRes.json();
    console.log(`[Vuelos] ${data.minifiedQuotations?.length || 0} resultados`);

    const vuelos = procesarVuelos(data);
    res.json({ ok: true, vuelos, total: data.minifiedQuotations?.length || 0 });
  } catch (err) {
    console.error('[Vuelos] Error:', err.message);
    if (err.message.includes('401')) tokenCache = { token: null, expiry: 0 };
    res.json({ ok: false, error: err.message });
  }
});

function procesarVuelos(data) {
  if (!data.minifiedQuotations) return [];
  const legsMap = {};
  const flightsMap = {};
  if (data.legs) data.legs.forEach(l => legsMap[l.legId] = l);
  if (data.flights) data.flights.forEach(f => flightsMap[f.flightId] = f);

  return data.minifiedQuotations
    .filter(q => !q.error)
    .slice(0, 30)
    .map(q => {
      const itinerario = q.legs.map(legId => {
        const leg = legsMap[legId];
        if (!leg) return null;
        const segmentos = (leg.flightIds || []).map(fId => {
          const f = flightsMap[fId];
          if (!f) return null;
          return {
            numero: `${f.marketingCarrier}${f.flightNumber}`,
            aerolinea: f.marketingCarrier,
            origen: f.departureAirportCode,
            destino: f.arrivalAirportCode,
            salida: f.departureDate,
            llegada: f.arrivalDate,
          };
        }).filter(Boolean);
        return {
          origen: leg.departureAirportCode || segmentos[0]?.origen,
          destino: leg.arrivalAirportCode || segmentos[segmentos.length-1]?.destino,
          salida: leg.departureDate || segmentos[0]?.salida,
          llegada: leg.arrivalDate || segmentos[segmentos.length-1]?.llegada,
          duracion: leg.totalDuration,
          escalas: Math.max(0, (leg.flightIds?.length || 1) - 1),
          segmentos
        };
      }).filter(Boolean);

      const equipaje = q.legsWithBaggageAllowance?.[0]?.baggageAllowance;
      return {
        id: q.quotationId,
        aerolinea: q.validatingCarrier,
        aerolineaDesc: q.sourceDescription || q.source,
        precio: q.grandTotalSellingPriceAmount,
        moneda: q.grandTotalSellingPriceCurrency || 'USD',
        expira: q.offerExpirationTimeCTZ,
        itinerario,
        maleta: equipaje?.checked?.[0]?.weight ? `${equipaje.checked[0].weight}${equipaje.checked[0].unit}` : 'Sin maleta',
        handBag: equipaje?.carryOn?.length > 0 ? 'Incluido' : 'No incluido'
      };
    })
    .sort((a, b) => a.precio - b.precio);
}

app.listen(PORT, () => console.log(`✅ Servidor en puerto ${PORT}`));

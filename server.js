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
  const body = new URLSearchParams({ mode: 'pass', username: SCIWEB_USER, password: SCIWEB_PASS, channel: 'GWC', defaultWholesalerId: WHOLESALER_ID });
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
app.get('/health', (req, res) => res.json({ ok: true, configured: !!(SCIWEB_USER && SCIWEB_PASS) }));

app.post('/buscar-vuelos', async (req, res) => {
  const { origen, destino, salida, regreso, adultos, ninos, infantes, stops } = req.body;
  console.log(`[Vuelos] ${origen}→${destino} | ${salida}-${regreso} | ${adultos}A ${ninos}N ${infantes}I`);
  try {
    const token = await getToken();
    const payload = {
      DepartCode: origen, ArrivalCode: destino,
      DepartDate: `${salida}T00:00:00`, ArrivalDate: `${regreso}T00:00:00`,
      ArrivalTime: null, DepartTime: null,
      Adults: parseInt(adultos), Childs: parseInt(ninos), Infants: parseInt(infantes),
      CabinType: null, Stops: stops !== undefined ? parseInt(stops) : null, Airlines: [],
      TypeOfFlightAllowedInItinerary: 3, SortByGLASAlgorithm: null,
      AlternateCurrencyCode: 'USD', CorporationCodeGlas: null, IncludeFiltersOptions: true
    };

    await fetch(`${API_BASE}/FlightSearchHistory/AddSearch`, {
      method: 'POST', headers: getHeaders(token),
      body: JSON.stringify({ SearchTravelType: 1, OneWayModel: null, MultipleLegsModel: null, RoundTripModel: payload })
    });

    const searchRes = await fetch(`${API_BASE}/FlightSearch/RoundTripRemake`, {
      method: 'POST', headers: getHeaders(token), body: JSON.stringify(payload)
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
  const legsMap = data.minifiedLegs || {};
  const airlinesMap = data.minifiedAirlinesInformation || {};

  return data.minifiedQuotations
    .filter(q => !q.error)
    .map(q => {
      const itinerario = q.legs.map(legId => {
        const leg = legsMap[legId];
        if (!leg) return null;

        // Segmentos del leg (vuelos individuales)
        const segmentos = [];
        if (leg.connectingCityCodesList) {
          // tiene escalas
          const ciudades = [leg.originAirportCode, ...leg.connectingCityCodesList, leg.destinationAirportCode];
          for (let i = 0; i < ciudades.length - 1; i++) {
            segmentos.push({ origen: ciudades[i], destino: ciudades[i+1] });
          }
        }

        const escalas = leg.connectingCityCodesList?.length || 0;
        return {
          legId,
          origen: leg.originAirportCode,
          destino: leg.destinationAirportCode,
          salida: leg.departure,
          llegada: leg.arrival,
          duracionMin: leg.elapsedFlightTimeInMinutes,
          duracion: leg.elapsedFlightTimeInMinutesFormatted,
          escalas,
          ciudadesEscala: leg.connectingCityCodesList || [],
          aerolineas: leg.involvedAirlines,
          tripDays: leg.tripDays || 0,
          overnight: leg.overNight || false
        };
      }).filter(Boolean);

      const equipaje = q.legsWithBaggageAllowance?.[0]?.baggageAllowance;
      const checkedBag = equipaje?.checked?.[0];
      const carryOn = equipaje?.carryOn?.[0];

      // Escalas totales del viaje (max de los dos tramos)
      const maxEscalas = Math.max(...itinerario.map(l => l.escalas));

      return {
        id: q.quotationId,
        aerolinea: q.validatingCarrier,
        aerolineaDesc: airlinesMap[q.validatingCarrier] || q.sourceDescription || q.source,
        precio: q.grandTotalSellingPriceAmount,
        moneda: q.grandTotalSellingPriceCurrency || 'USD',
        expira: q.offerExpirationTimeCTZ,
        itinerario,
        escalas: maxEscalas,
        maleta: checkedBag ? (checkedBag.pieces > 0 ? `${checkedBag.pieces} maleta` : checkedBag.weight ? `${checkedBag.weight}${checkedBag.unit}` : 'Sin maleta') : 'Sin maleta',
        handBag: carryOn ? 'Incluido' : 'No incluido',
        source: q.source
      };
    })
    .sort((a, b) => a.precio - b.precio);
}

app.listen(PORT, () => console.log(`✅ Servidor en puerto ${PORT}`));

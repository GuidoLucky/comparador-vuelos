const express = require('express');
const path = require('path');
const crypto = require('crypto');
const app = express();
app.use(express.json());

// ─── AUTH: Sessions ───
const sessions = new Map(); // token → { userId, nombre, usuario, rol, expiry }
const COOKIE_NAME = 'lt_session';
const SESSION_TTL = 24 * 60 * 60 * 1000; // 24h

function hashPassword(password, salt) {
  salt = salt || crypto.randomBytes(16).toString('hex');
  const hash = crypto.pbkdf2Sync(password, salt, 10000, 64, 'sha512').toString('hex');
  return { salt, hash };
}

function verifyPassword(password, salt, storedHash) {
  const { hash } = hashPassword(password, salt);
  return hash === storedHash;
}

function createSession(user) {
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, { userId: user.id, nombre: user.nombre, usuario: user.usuario, rol: user.rol, expiry: Date.now() + SESSION_TTL });
  return token;
}

function parseCookies(req) {
  const cookies = {};
  (req.headers.cookie || '').split(';').forEach(c => {
    const [k, v] = c.trim().split('=');
    if (k) cookies[k] = v;
  });
  return cookies;
}

// Auth middleware
function authMiddleware(req, res, next) {
  // Skip auth for login routes and static assets
  if (req.path === '/login' || req.path === '/login.html' || req.path === '/api/login' || req.path === '/api/logout') {
    return next();
  }
  // Allow static files (css, js, images, fonts)
  if (/\.(css|js|png|jpg|svg|ico|woff|ttf|eot)$/i.test(req.path)) return next();
  
  const cookies = parseCookies(req);
  const token = cookies[COOKIE_NAME];
  if (token && sessions.has(token)) {
    const session = sessions.get(token);
    if (Date.now() < session.expiry) {
      req.user = session;
      return next();
    }
    sessions.delete(token);
  }
  // Not authenticated
  if (req.path.startsWith('/api/') || req.headers.accept?.includes('json')) {
    return res.status(401).json({ ok: false, error: 'No autenticado' });
  }
  return res.redirect('/login.html');
}

// Serve login page (before auth middleware)
app.get('/login.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.use(authMiddleware);
app.use(express.static('public'));

// Ruta explícita para reservas.html (fallback si static no lo encuentra)
app.get('/reservas.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'reservas.html'));
});

// ─── AUTH ENDPOINTS ───
app.post('/api/login', async (req, res) => {
  const { usuario, password } = req.body;
  if (!usuario || !password) return res.json({ ok: false, error: 'Usuario y contraseña requeridos' });
  if (!db) return res.json({ ok: false, error: 'DB no disponible' });
  try {
    const r = await db.query('SELECT * FROM usuarios WHERE usuario=$1 AND activo=true', [usuario]);
    if (!r.rows.length) return res.json({ ok: false, error: 'Usuario o contraseña incorrectos' });
    const user = r.rows[0];
    if (!verifyPassword(password, user.password_salt, user.password_hash)) {
      return res.json({ ok: false, error: 'Usuario o contraseña incorrectos' });
    }
    const token = createSession(user);
    res.setHeader('Set-Cookie', `${COOKIE_NAME}=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${SESSION_TTL/1000}`);
    res.json({ ok: true, nombre: user.nombre, rol: user.rol });
  } catch(e) { res.json({ ok: false, error: e.message }); }
});

app.post('/api/logout', (req, res) => {
  const cookies = parseCookies(req);
  const token = cookies[COOKIE_NAME];
  if (token) sessions.delete(token);
  res.setHeader('Set-Cookie', `${COOKIE_NAME}=; Path=/; HttpOnly; Max-Age=0`);
  res.json({ ok: true });
});

app.get('/api/me', (req, res) => {
  if (!req.user) return res.status(401).json({ ok: false });
  res.json({ ok: true, nombre: req.user.nombre, usuario: req.user.usuario, rol: req.user.rol });
});

// ─── ADMIN: Gestión de usuarios ───
app.get('/api/usuarios', async (req, res) => {
  if (req.user?.rol !== 'admin') return res.status(403).json({ ok: false, error: 'Sin permisos' });
  try {
    const r = await db.query(`SELECT u.id, u.nombre, u.usuario, u.rol, u.activo, u.created_at,
      json_agg(json_build_object('proveedor', uc.proveedor, 'cred_user', uc.cred_user, 'activo', uc.activo)) FILTER (WHERE uc.id IS NOT NULL) as credenciales
      FROM usuarios u LEFT JOIN usuario_credenciales uc ON uc.usuario_id = u.id
      GROUP BY u.id ORDER BY u.id`);
    res.json({ ok: true, usuarios: r.rows });
  } catch(e) { res.json({ ok: false, error: e.message }); }
});

app.post('/api/usuarios', async (req, res) => {
  if (req.user?.rol !== 'admin') return res.status(403).json({ ok: false, error: 'Sin permisos' });
  const { nombre, usuario, password, rol } = req.body;
  if (!nombre || !usuario || !password) return res.json({ ok: false, error: 'Nombre, usuario y contraseña requeridos' });
  try {
    const { salt, hash } = hashPassword(password);
    const r = await db.query(`INSERT INTO usuarios (nombre, usuario, password_hash, password_salt, rol) VALUES ($1,$2,$3,$4,$5) RETURNING id`,
      [nombre, usuario, hash, salt, rol || 'vendedor']);
    res.json({ ok: true, id: r.rows[0].id });
  } catch(e) {
    if (e.message.includes('unique')) return res.json({ ok: false, error: 'El usuario ya existe' });
    res.json({ ok: false, error: e.message });
  }
});

app.put('/api/usuarios/:id', async (req, res) => {
  if (req.user?.rol !== 'admin') return res.status(403).json({ ok: false, error: 'Sin permisos' });
  const { nombre, password, rol, activo } = req.body;
  try {
    if (password) {
      const { salt, hash } = hashPassword(password);
      await db.query('UPDATE usuarios SET nombre=COALESCE($1,nombre), password_hash=$2, password_salt=$3, rol=COALESCE($4,rol), activo=COALESCE($5,activo) WHERE id=$6',
        [nombre, hash, salt, rol, activo, req.params.id]);
    } else {
      await db.query('UPDATE usuarios SET nombre=COALESCE($1,nombre), rol=COALESCE($2,rol), activo=COALESCE($3,activo) WHERE id=$4',
        [nombre, rol, activo, req.params.id]);
    }
    res.json({ ok: true });
  } catch(e) { res.json({ ok: false, error: e.message }); }
});

// ─── ADMIN: Credenciales por proveedor ───
app.post('/api/usuarios/:id/credenciales', async (req, res) => {
  if (req.user?.rol !== 'admin') return res.status(403).json({ ok: false, error: 'Sin permisos' });
  const { proveedor, cred_user, cred_pass, cred_extra } = req.body;
  try {
    await db.query(`INSERT INTO usuario_credenciales (usuario_id, proveedor, cred_user, cred_pass, cred_extra)
      VALUES ($1,$2,$3,$4,$5) ON CONFLICT (usuario_id, proveedor) DO UPDATE SET cred_user=$3, cred_pass=$4, cred_extra=$5, activo=true`,
      [req.params.id, proveedor, cred_user, cred_pass, JSON.stringify(cred_extra || {})]);
    res.json({ ok: true });
  } catch(e) { res.json({ ok: false, error: e.message }); }
});

// ─── Per-user credential helpers ───
async function getUserCredentials(userId, proveedor) {
  if (!db) return null;
  const r = await db.query('SELECT * FROM usuario_credenciales WHERE usuario_id=$1 AND proveedor=$2 AND activo=true', [userId, proveedor]);
  return r.rows[0] || null;
}

// Per-user token caches
const userTokenCaches = {}; // userId → { tucano: {token, expiry}, gea: {token, expiry} }

async function getUserTucanoToken(userId) {
  const cache = userTokenCaches[userId]?.tucano;
  if (cache?.token && Date.now() < cache.expiry) return cache.token;
  
  const cred = await getUserCredentials(userId, 'tucano');
  if (!cred) return await getToken(); // Fallback to global
  
  const body = new URLSearchParams({ mode:'pass', username: cred.cred_user, password: cred.cred_pass, channel:'GWC', defaultWholesalerId: WHOLESALER_ID });
  const res = await fetch(`${API_BASE}/Account/token`, {
    method:'POST',
    headers:{ 'Content-Type':'application/x-www-form-urlencoded', 'Origin':'https://sciweb.tucanotours.com.ar', 'Referer':'https://sciweb.tucanotours.com.ar/' },
    body: body.toString()
  });
  const data = await res.json();
  const token = data.access_token || data.token || data.Token || data.AccessToken;
  if (!token) throw new Error('Token Tucano inválido');
  
  if (!userTokenCaches[userId]) userTokenCaches[userId] = {};
  userTokenCaches[userId].tucano = { token, expiry: Date.now() + 50*60*1000 };
  return token;
}

async function getUserLleegoToken(userId) {
  const cache = userTokenCaches[userId]?.gea;
  if (cache?.token && Date.now() < cache.expiry) return cache.token;
  
  const cred = await getUserCredentials(userId, 'gea');
  if (!cred) return await getLleegoToken(); // Fallback to global
  
  const extra = typeof cred.cred_extra === 'string' ? JSON.parse(cred.cred_extra) : (cred.cred_extra || {});
  const agent = extra.agent || 'GFinkelstein';
  
  const authRes = await fetch('https://api-tr.lleego.com/api/v2/auth/login?locale=es-ar', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-api-key': LLEEGO_API_KEY },
    body: JSON.stringify({ username: cred.cred_user, password: cred.cred_pass, agent })
  });
  if (!authRes.ok) return await getLleegoToken(); // Fallback
  const authData = await authRes.json();
  const token = authData.token;
  if (!token) return await getLleegoToken();
  
  if (!userTokenCaches[userId]) userTokenCaches[userId] = {};
  userTokenCaches[userId].gea = { token, expiry: Date.now() + 50*60*1000 };
  return token;
}

const PORT = process.env.PORT || 3000;
const SCIWEB_USER = process.env.SCIWEB_USER;
const SCIWEB_PASS = process.env.SCIWEB_PASS;
const API_BASE = 'https://api-gwc.glas.travel/api';
const COMPANY_ID = '3036';
const WHOLESALER_ID = '538';

// DB
const db = require('./db');

// Migración: agregar columnas faltantes + tablas de usuarios
if (db) {
  (async () => {
    try {
      await db.query(`ALTER TABLE reservas ADD COLUMN IF NOT EXISTS notas TEXT`);
      await db.query(`ALTER TABLE reservas ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT NOW()`);
      await db.query(`ALTER TABLE reservas ADD COLUMN IF NOT EXISTS vendedor TEXT`);
      await db.query(`ALTER TABLE reservas ADD COLUMN IF NOT EXISTS precio_venta_usd NUMERIC`);
      await db.query(`ALTER TABLE reservas ADD COLUMN IF NOT EXISTS emision_data JSONB`);
      await db.query(`ALTER TABLE reservas ADD COLUMN IF NOT EXISTS penalidades_json JSONB`);
      await db.query(`ALTER TABLE reservas ADD COLUMN IF NOT EXISTS usuario_id INTEGER`);
      
      // Tabla de usuarios
      await db.query(`CREATE TABLE IF NOT EXISTS usuarios (
        id SERIAL PRIMARY KEY,
        nombre TEXT NOT NULL,
        usuario TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        password_salt TEXT NOT NULL,
        rol TEXT DEFAULT 'vendedor',
        activo BOOLEAN DEFAULT true,
        created_at TIMESTAMPTZ DEFAULT NOW()
      )`);
      
      // Tabla de credenciales por proveedor
      await db.query(`CREATE TABLE IF NOT EXISTS usuario_credenciales (
        id SERIAL PRIMARY KEY,
        usuario_id INTEGER REFERENCES usuarios(id),
        proveedor TEXT NOT NULL,
        cred_user TEXT,
        cred_pass TEXT,
        cred_extra JSONB DEFAULT '{}',
        activo BOOLEAN DEFAULT true,
        UNIQUE(usuario_id, proveedor)
      )`);
      
      // Crear admin por defecto si no existe
      const adminExists = await db.query("SELECT id FROM usuarios WHERE usuario='guido'");
      if (!adminExists.rows.length) {
        const { salt, hash } = hashPassword('admin123');
        await db.query(`INSERT INTO usuarios (nombre, usuario, password_hash, password_salt, rol) VALUES ($1,$2,$3,$4,$5)`,
          ['Guido Finkelstein', 'guido', hash, salt, 'admin']);
        console.log('[DB] Usuario admin creado: guido / admin123');
        
        // Vincular credenciales actuales al admin
        const adminUser = await db.query("SELECT id FROM usuarios WHERE usuario='guido'");
        const adminId = adminUser.rows[0].id;
        await db.query(`INSERT INTO usuario_credenciales (usuario_id, proveedor, cred_user, cred_pass, cred_extra) VALUES 
          ($1, 'tucano', $2, $3, '{}'),
          ($1, 'gea', $4, $5, $6)
          ON CONFLICT DO NOTHING`,
          [adminId, SCIWEB_USER, SCIWEB_PASS, LLEEGO_EMAIL, LLEEGO_PASS, JSON.stringify({ agent: LLEEGO_AGENT })]);
      }
      
      console.log('[DB] Migración OK');
    } catch(e) { console.warn('[DB] Migración:', e.message); }
  })();
}

let tokenCache = { token: null, expiry: 0 };

// ─── LLEEGO / GEA ───
const LLEEGO_EMAIL = process.env.LLEEGO_EMAIL || 'ventas@luckytourviajes.com';
const LLEEGO_PASS = process.env.LLEEGO_PASS || 't7pmgrxr0V';
const LLEEGO_AGENT = process.env.LLEEGO_AGENT || 'GFinkelstein';
const LLEEGO_API_KEY = 'RD7dLSjYqT18InSheQfKLvpANUzNVvEG';
let lleegoTokenCache = { token: null, expiry: 0 };

// ─── SABRE DIRECT ───
const SABRE_USER_ID = process.env.SABRE_USER_ID || 'V1:pxkjaapqxykqfduj:DEVCENTER:EXT';
const SABRE_PASSWORD = process.env.SABRE_PASSWORD || '59buNJbD';
const SABRE_PCC = process.env.SABRE_PCC || '42LJ';
const SABRE_API_BASE = 'https://api-crt.cert.havail.sabre.com'; // CERT (DEVCENTER)
let sabreTokenCache = { token: null, expiry: 0 };

async function getSabreToken() {
  if (sabreTokenCache.token && Date.now() < sabreTokenCache.expiry) return sabreTokenCache.token;
  try {
    // Sabre OAuth2: base64(base64(userId):base64(password))
    const encodedUser = Buffer.from(SABRE_USER_ID).toString('base64');
    const encodedPass = Buffer.from(SABRE_PASSWORD).toString('base64');
    const credentials = Buffer.from(`${encodedUser}:${encodedPass}`).toString('base64');
    
    const res = await fetch(`${SABRE_API_BASE}/v2/auth/token`, {
      method: 'POST',
      headers: {
        'Authorization': `Basic ${credentials}`,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: 'grant_type=client_credentials'
    });
    if (!res.ok) {
      const errText = await res.text();
      console.log('[Sabre] Auth error:', res.status, errText.substring(0, 500));
      return null;
    }
    const data = await res.json();
    sabreTokenCache = { token: data.access_token, expiry: Date.now() + (data.expires_in || 600) * 1000 - 30000 };
    console.log('[Sabre] Token obtenido OK');
    return data.access_token;
  } catch(e) {
    console.error('[Sabre] Auth error:', e.message);
    return null;
  }
}

// ─── SABRE: Bargain Finder Max Search ───
async function buscarSabre({ tipo, origen, destino, salida, regreso, adultos, ninos, infantes, cabinType, stops, tramos }) {
  const token = await getSabreToken();
  if (!token) return [];
  try {
    const adtCount = parseInt(adultos) || 1;
    const chdCount = parseInt(ninos) || 0;
    const infCount = parseInt(infantes) || 0;
    
    const paxTypes = [];
    if (adtCount > 0) paxTypes.push({ Code: 'ADT', Quantity: adtCount });
    if (chdCount > 0) paxTypes.push({ Code: 'CNN', Quantity: chdCount });
    if (infCount > 0) paxTypes.push({ Code: 'INF', Quantity: infCount });

    // Build origin-destination
    const originDest = [];
    if (tipo === 'multidestino' && tramos) {
      for (const t of tramos) {
        originDest.push({
          DepartureDateTime: `${t.salida}T00:00:00`,
          OriginLocation: { LocationCode: t.origen },
          DestinationLocation: { LocationCode: t.destino }
        });
      }
    } else {
      originDest.push({
        DepartureDateTime: `${salida}T00:00:00`,
        OriginLocation: { LocationCode: origen },
        DestinationLocation: { LocationCode: destino }
      });
      if (tipo !== 'oneway' && regreso) {
        originDest.push({
          DepartureDateTime: `${regreso}T00:00:00`,
          OriginLocation: { LocationCode: destino },
          DestinationLocation: { LocationCode: origen }
        });
      }
    }
    
    // BFM v5 request (matching Sabre's exact format)
    const bfmBody = {
      OTA_AirLowFareSearchRQ: {
        Version: '5',
        POS: {
          Source: [{ PseudoCityCode: SABRE_PCC, RequestorID: { Type: '1', ID: '1', CompanyName: { Code: 'TN' } } }]
        },
        OriginDestinationInformation: originDest,
        TravelPreferences: {},
        TravelerInfoSummary: {
          AirTravelerAvail: [{ PassengerTypeQuantity: paxTypes }]
        },
        TPA_Extensions: {
          IntelliSellTransaction: { RequestType: { Name: '50ITINS' } }
        }
      }
    };
    
    // Add stops filter
    if (stops === '0' || stops === 0) {
      bfmBody.OTA_AirLowFareSearchRQ.TravelPreferences.MaxStopsQuantity = 0;
    }
    
    console.log('[Sabre] BFM v5 request:', JSON.stringify(bfmBody).substring(0, 600));
    
    const res = await fetch(`${SABRE_API_BASE}/v5/offers/shop`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(bfmBody)
    });
    
    if (!res.ok) {
      const errText = await res.text();
      console.log('[Sabre] BFM error:', res.status, errText.substring(0, 1000));
      return [];
    }
    
    const data = await res.json();
    return procesarVuelosSabre(data, { adultos: adtCount, ninos: chdCount, infantes: infCount });
  } catch(e) {
    console.error('[Sabre] Search error:', e.message);
    return [];
  }
}

// Cache for Sabre solutions
const sabreSolutionsCache = new Map();

function procesarVuelosSabre(data, paxCounts) {
  const results = [];
  try {
    const resp = data.groupedItineraryResponse || data;
    if (!resp) { console.log('[Sabre] No groupedItineraryResponse'); return []; }
    
    // Build lookup maps from Descs
    const scheduleMap = {};
    (resp.scheduleDescs || []).forEach(s => { scheduleMap[s.id] = s; });
    const legMap = {};
    (resp.legDescs || []).forEach(l => { legMap[l.id] = l; });
    const taxMap = {};
    (resp.taxDescs || []).forEach(t => { taxMap[t.id] = t; });
    const baggageMap = {};
    (resp.baggageAllowanceDescs || []).forEach(b => { baggageMap[b.id] = b; });
    const validatingCarrierMap = {};
    (resp.validatingCarrierDescs || []).forEach(v => { validatingCarrierMap[v.id] = v; });
    
    const itinGroups = resp.itineraryGroups || [];
    console.log(`[Sabre] ${itinGroups.length} itinerary groups`);
    
    for (const group of itinGroups) {
      const groupLegs = group.groupDescription?.legDescriptions || [];
      const itineraries = group.itineraries || [];
      
      for (const itin of itineraries) {
        try {
          const legRefs = itin.legs || [];
          const pricingInfos = itin.pricingInformation || [];
          if (!pricingInfos.length) continue;
          
          const pricing = pricingInfos[0]; // Take first/cheapest pricing
          const fare = pricing.fare || {};
          const totalFare = fare.totalFare || {};
          const totalUSD = totalFare.totalPrice || 0;
          const currency = totalFare.currency || 'USD';
          
          // Validating carrier
          const vcRefs = fare.validatingCarriers || [];
          let validatingCarrier = fare.validatingCarrierCode || '';
          if (!validatingCarrier && vcRefs.length) {
            const vc = validatingCarrierMap[vcRefs[0].ref];
            validatingCarrier = vc?.default?.code || '';
          }
          
          // Per-pax breakdown from passengerInfoList
          const fareList = [];
          const paxInfoList = fare.passengerInfoList || [];
          for (const paxEntry of paxInfoList) {
            const pi = paxEntry.passengerInfo || {};
            const paxType = pi.passengerType || 'ADT';
            const paxNum = pi.passengerNumber || 1;
            const paxFare = pi.passengerTotalFare || {};
            const paxTotal = paxFare.totalFare || 0;
            const paxTax = paxFare.totalTaxAmount || 0;
            const paxBase = paxFare.equivalentAmount || (paxTotal - paxTax);
            fareList.push({
              passenger_type: paxType, quantity: paxNum,
              base: paxBase, total_taxes: paxTax, total: paxTotal
            });
            
            // Baggage from this pax
            // (handled below)
          }
          
          // Build legs from refs
          const legs = [];
          for (let li = 0; li < legRefs.length; li++) {
            const legDesc = legMap[legRefs[li].ref];
            if (!legDesc) continue;
            
            const depDate = groupLegs[li]?.departureDate || '';
            const schedules = legDesc.schedules || [];
            const legSegs = [];
            
            for (const schedRef of schedules) {
              const sched = scheduleMap[schedRef.ref];
              if (!sched) continue;
              
              const dep = sched.departure || {};
              const arr = sched.arrival || {};
              const carrier = sched.carrier || {};
              
              // Build full datetime
              const depTime = dep.time || '00:00:00';
              const depDT = depDate ? `${depDate}T${depTime.split('+')[0].split('-')[0]}` : '';
              
              // Calculate arrival date (might be next day)
              let arrDT = depDT; // approximate
              if (dep.time && arr.time) {
                arrDT = `${depDate}T${arr.time.split('+')[0].split('-')[0]}`;
              }
              
              legSegs.push({
                origen: dep.airport || '',
                destino: arr.airport || '',
                salida: depDT,
                llegada: arrDT,
                vuelo: `${carrier.marketing || ''}${carrier.marketingFlightNumber || ''}`,
                aerolinea: carrier.marketing || '',
                operador: carrier.operating || carrier.marketing || '',
                cabina: 'Y',
                duracion: sched.elapsedTime || 0
              });
            }
            
            if (!legSegs.length) continue;
            const firstSeg = legSegs[0];
            const lastSeg = legSegs[legSegs.length - 1];
            legs.push({
              origen: firstSeg.origen,
              destino: lastSeg.destino,
              origenCiudad: AIRPORT_CITY_MAP[firstSeg.origen] || firstSeg.origen,
              destinoCiudad: AIRPORT_CITY_MAP[lastSeg.destino] || lastSeg.destino,
              salida: firstSeg.salida,
              llegada: lastSeg.llegada,
              escalas: legSegs.length - 1,
              segmentos: legSegs
            });
          }
          
          if (!legs.length) continue;
          
          const mainAirline = validatingCarrier || legs[0].segmentos[0]?.aerolinea || '';
          const totalEscalas = legs.reduce((s, l) => s + l.escalas, 0);
          const totalPax = (paxCounts.adultos || 1) + (paxCounts.ninos || 0) + (paxCounts.infantes || 0);
          const precioPerPax = totalPax > 0 ? Math.round(totalUSD / totalPax * 100) / 100 : totalUSD;
          const tipoVuelo = legs.length > 2 ? 'multidestino' : (legs.length === 2 ? 'roundtrip' : 'oneway');
          
          // Baggage info
          let equipaje = {
            handOn: { label: 'Incluida', incluido: true },
            carryOn: { label: 'No informado', incluido: false },
            checked: { label: 'No informado', incluido: false }
          };
          try {
            for (const paxEntry of paxInfoList) {
              const pi = paxEntry.passengerInfo || {};
              const bagInfos = pi.baggageInformation || [];
              for (const bag of bagInfos) {
                const allowance = baggageMap[bag.allowance?.ref];
                if (allowance) {
                  if (allowance.pieceCount !== undefined) {
                    if (allowance.pieceCount > 0) {
                      equipaje.checked = { label: `${allowance.pieceCount}x 23KG`, incluido: true };
                    } else {
                      equipaje.checked = { label: 'No incluida', incluido: false };
                    }
                  }
                  if (allowance.weight) {
                    equipaje.checked = { label: `${allowance.weight}${allowance.unit || 'kg'}`, incluido: true };
                  }
                }
              }
              break; // Only first pax
            }
          } catch(e) {}
          
          // Cache solution
          const solId = `sabre_${Date.now()}_${Math.random().toString(36).substr(2,6)}`;
          sabreSolutionsCache.set(solId, { 
            itin, pricing, fare, legs, paxCounts, fareList,
            validatingCarrier, totalUSD, currency
          });
          
          results.push({
            source: 'sabre',
            fuente: 'Sabre',
            gds: 'Sabre',
            quotationId: solId,
            aerolinea: mainAirline,
            aerolineaDesc: mainAirline,
            precioTotal: totalUSD,
            precioUSD: totalUSD,
            precioPerPax,
            moneda: currency,
            tipo: tipoVuelo,
            escalas: totalEscalas,
            itinerario: legs.map(l => ({
              origen: l.origen, destino: l.destino,
              origenCiudad: l.origenCiudad, destinoCiudad: l.destinoCiudad,
              salida: l.salida, llegada: l.llegada,
              escalas: l.escalas, segmentos: l.segmentos
            })),
            equipaje,
            fareList
          });
        } catch(itinErr) {
          console.error('[Sabre] Itin parse error:', itinErr.message);
        }
      }
    }
    
    console.log(`[Sabre] ${results.length} vuelos procesados`);
  } catch(e) {
    console.error('[Sabre] Parse error:', e.message);
  }
  return results;
}


// Mapa global de códigos IATA → ciudades (para normalizar nombres de aeropuertos)
const AIRPORT_CITY_MAP = {
  'EZE':'Buenos Aires','AEP':'Buenos Aires','MIA':'Miami','MAD':'Madrid','BCN':'Barcelona',
  'FCO':'Roma','CDG':'París','ORY':'París','LHR':'Londres','LGW':'Londres','FRA':'Frankfurt',
  'AMS':'Amsterdam','IST':'Estambul','SAW':'Estambul','DXB':'Dubai','DOH':'Doha',
  'TLV':'Tel Aviv','ADD':'Addis Abeba','GRU':'San Pablo','GIG':'Río de Janeiro',
  'SCL':'Santiago','LIM':'Lima','BOG':'Bogotá','PTY':'Panamá','CUN':'Cancún',
  'MEX':'México DF','JFK':'Nueva York','EWR':'Nueva York','LAX':'Los Ángeles',
  'ORD':'Chicago','ATL':'Atlanta','DFW':'Dallas','CLT':'Charlotte','PHL':'Filadelfia',
  'MVD':'Montevideo','ASU':'Asunción','COR':'Córdoba','MDZ':'Mendoza','BRC':'Bariloche',
  'IGR':'Iguazú','FTE':'El Calafate','USH':'Ushuaia','NQN':'Neuquén','ROS':'Rosario',
  'SLA':'Salta','TUC':'Tucumán','JUJ':'Jujuy','PMC':'Puerto Montt','PUQ':'Punta Arenas',
  'SSA':'Salvador','REC':'Recife','FOR':'Fortaleza','FLN':'Florianópolis',
  'SDU':'Río de Janeiro','CNF':'Belo Horizonte','CWB':'Curitiba','POA':'Porto Alegre',
  'VCP':'Campinas','BSB':'Brasilia','MXP':'Milán','LIN':'Milán','MUC':'Múnich',
  'ZRH':'Zúrich','VIE':'Viena','CPH':'Copenhague','OSL':'Oslo','ARN':'Estocolmo',
  'HEL':'Helsinki','WAW':'Varsovia','PRG':'Praga','BUD':'Budapest','OTP':'Bucarest',
  'ATH':'Atenas','LIS':'Lisboa','OPO':'Oporto','DUB':'Dublín','EDI':'Edimburgo',
  'BRU':'Bruselas','GVA':'Ginebra','NCE':'Niza','MRS':'Marsella','LYS':'Lyon',
  'NRT':'Tokio','HND':'Tokio','ICN':'Seúl','PEK':'Pekín','PVG':'Shanghái',
  'HKG':'Hong Kong','SIN':'Singapur','BKK':'Bangkok','DEL':'Delhi','BOM':'Bombay',
  'SYD':'Sídney','MEL':'Melbourne','AKL':'Auckland','JNB':'Johannesburgo',
  'CAI':'El Cairo','CMN':'Casablanca','NBO':'Nairobi','CPT':'Ciudad del Cabo',
  'SFO':'San Francisco','BOS':'Boston','SEA':'Seattle','DEN':'Denver','MSP':'Minneapolis',
  'DTW':'Detroit','IAH':'Houston','FLL':'Fort Lauderdale','MCO':'Orlando','TPA':'Tampa',
};
// Cache de soluciones Lleego para Ver precio / Reservar
const lleegoSolutionsCache = new Map(); // key: lleego_SOLID → raw solution data
const penaltiesCache = new Map(); // key: quotationId → penalidades object
// Limpiar cache cada 30 min (las soluciones expiran)
setInterval(() => { if (lleegoSolutionsCache.size > 500) lleegoSolutionsCache.clear(); }, 30*60*1000);

async function getLleegoToken() {
  if (lleegoTokenCache.token && Date.now() < lleegoTokenCache.expiry) return lleegoTokenCache.token;
  try {
    const url = `https://middle.lleego.com/api/user/auto-login?e=${encodeURIComponent(LLEEGO_EMAIL)}&w=${encodeURIComponent(LLEEGO_PASS)}&idAgente=${encodeURIComponent(LLEEGO_AGENT)}`;
    const r = await fetch(url, {
      headers: { 'Accept': 'application/json', 'Content-Type': 'application/json', 'env': 'geaargentina', 'lang': 'es-ar' }
    });
    if (!r.ok) throw new Error(`Lleego auth ${r.status}`);
    const data = await r.json();
    if (!data.token) throw new Error('No token in Lleego response');
    // JWT exp is ~1 hour, use 50 min
    lleegoTokenCache = { token: data.token, expiry: Date.now() + 50 * 60 * 1000 };
    console.log('[Lleego] Token obtenido OK');
    return data.token;
  } catch(e) {
    console.error('[Lleego] Auth error:', e.message);
    return null;
  }
}

async function buscarLleego({ tipo, origen, destino, salida, regreso, adultos, ninos, infantes, cabinType, stops, tramos }) {
  const token = await getLleegoToken();
  if (!token) return [];
  try {
    // Build pax ages array
    const ages = [];
    for (let i = 0; i < (parseInt(adultos)||1); i++) ages.push(30);
    for (let i = 0; i < (parseInt(ninos)||0); i++) ages.push(8);
    for (let i = 0; i < (parseInt(infantes)||0); i++) ages.push(1);

    // Cabin mapping: GLAS uses 0=all,1=economy,2=premium,3=business,4=first
    const cabinMap = { '1': 'Y', '2': 'W', '3': 'C', '4': 'F' };
    const cabin = cabinMap[String(cabinType)] || '';
    const stopsVal = (stops !== null && stops !== undefined && stops !== '') ? parseInt(stops) : null;

    // Build journeys
    const journeys = [];
    if (tipo === 'multidestino' && Array.isArray(tramos)) {
      for (const t of tramos) {
        const j = { origin: t.origen, destination: t.destino, date: t.salida };
        if (stopsVal !== null) j.max_layover_count = stopsVal;
        journeys.push(j);
      }
    } else {
      const j1 = { origin: origen, destination: destino, date: salida };
      if (stopsVal !== null) j1.max_layover_count = stopsVal;
      journeys.push(j1);
      if (tipo === 'roundtrip' && regreso) {
        const j2 = { origin: destino, destination: origen, date: regreso };
        if (stopsVal !== null) j2.max_layover_count = stopsVal;
        journeys.push(j2);
      }
    }

    const travelOpts = {
      companies: [["ADD"]],
      currency: 'USD',
      include_train: false, include_bus: false,
      include_gds: true, include_ndc: true, low_cost: false,
      only_flight: true,
      exclude_fares: ['CUPO'],
      journeys,
      paxes_distribution: { passengers_ages: ages }
    };
    if (cabin) travelOpts.cabin = cabin;

    const body = {
      query: {
        criterias: [{
          rule: { combined: false, duplicated: false, show_data: true, show_partial: false, only_partial: false },
          travel: travelOpts
        }]
      }
    };

    console.log(`[Lleego] Buscando ${origen}-${destino} ${salida}${regreso ? '/'+regreso : ''} ${ages.length}pax cabin=${cabin}`);
    console.log(`[Lleego] Request body:`, JSON.stringify(body).substring(0, 500));
    const r = await fetch('https://api-tr.lleego.com/api/v2/transport/avail?locale=es-ar', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
        'x-api-key': LLEEGO_API_KEY,
        'lang': 'es-ar'
      },
      body: JSON.stringify(body)
    });
    if (!r.ok) {
      const txt = await r.text().catch(()=>'');
      console.error(`[Lleego] Error ${r.status}: ${txt.substring(0,200)}`);
      if (r.status === 401) lleegoTokenCache = { token: null, expiry: 0 };
      return [];
    }
    const resp = await r.json();
    const topKeys = Object.keys(resp);
    const dataKeys = resp.data ? Object.keys(resp.data) : [];
    const solCount = resp.data?.solutions?.length || resp.solutions?.length || 0;
    console.log(`[Lleego] ${solCount} soluciones | topKeys: ${topKeys.join(',')} | dataKeys: ${dataKeys.join(',')}`);
    if (solCount === 0) {
      console.log(`[Lleego] Raw resp sample:`, JSON.stringify(resp).substring(0, 500));
    }
    return procesarVuelosLleego(resp, { adultos: parseInt(adultos)||1, ninos: parseInt(ninos)||0, infantes: parseInt(infantes)||0 });
  } catch(e) {
    console.error('[Lleego] Search error:', e.message);
    return [];
  }
}

function procesarVuelosLleego(resp, paxCounts = { adultos: 1, ninos: 0, infantes: 0 }) {
  // Top-level: solutions, segments, journeys, fares
  // Under resp.data: port, currency, company, provider
  const solutions = resp.solutions || [];
  const segments = resp.segments || {};
  const journeys = resp.journeys || {};
  const fares = resp.fares || {};
  const companies = resp.data?.company || {};
  const ports = resp.data?.port || {};
  const providers = resp.data?.provider || {};

  if (!solutions.length || !Object.keys(segments).length) {
    console.log(`[Lleego] No solutions or segments to process`);
    return [];
  }

  return solutions.map((sol, solIdx) => {
    try {
      // Cache raw solution + shared data for later use
      const searchToken = resp.token || '';
      lleegoSolutionsCache.set(`lleego_${sol.id}`, { sol, segments, journeys, fares, companies, providers, ports, searchToken, paxCounts });
      
      // Log first solution structure for debugging
      if (solIdx === 0) {
        console.log('[Lleego] First sol keys:', Object.keys(sol));
        console.log('[Lleego] First sol.data keys:', Object.keys(sol.data || {}));
        console.log('[Lleego] First sol.total_price:', JSON.stringify(sol.total_price));
        // Log fare_list for per-pax pricing
        const fareList = sol.data?.fare_list || [];
        console.log('[Lleego] First sol fare_list count:', fareList.length);
        if (fareList.length) console.log('[Lleego] First fare_list:', JSON.stringify(fareList).substring(0, 1500));
        // Log fares dict entries referenced by fare_list
        for (const fl of fareList.slice(0, 3)) {
          const fareRef = fl.fare_reference || fl.fare_id || fl.ref || fl;
          const fareData = fares[fareRef] || fares[fl] || null;
          if (fareData) console.log(`[Lleego] Fare ${fareRef}:`, JSON.stringify(fareData).substring(0, 500));
        }
        const a0 = (sol.data?.associations || [])[0];
        if (a0) {
          console.log('[Lleego] First assoc keys:', Object.keys(a0));
        }
      }
      // Get associations (ida y vuelta)
      const assocs = sol.data?.associations || [];
      const itinerario = [];
      let maxEscalas = 0;

      for (const assoc of assocs) {
        const journeyRefs = assoc.journey_references || [];
        const segRefs = assoc.segment_references || {};
        for (const jRef of journeyRefs) {
          const journey = journeys[jRef];
          if (!journey) continue;
          const jSegs = journey.segments || [];
          const escalas = journey.layovers || 0;
          if (escalas > maxEscalas) maxEscalas = escalas;
          
          // One itinerario entry per journey (ida/vuelta), not per segment
          const firstSeg = segments[jSegs[0]];
          const lastSeg = segments[jSegs[jSegs.length - 1]] || firstSeg;
          if (!firstSeg) continue;

          const ciudadesEscala = jSegs.length > 1 
            ? jSegs.slice(0, -1).map(sid => segments[sid]?.arrival).filter(Boolean) 
            : [];

          // Build per-segment info for PDF (like Tucano's flightsInformation)
          const segmentos = jSegs.map(sid => {
            const seg = segments[sid];
            if (!seg) return null;
            const depPort = ports[seg.departure] || {};
            const arrPort = ports[seg.arrival] || {};
            return {
              origen: seg.departure,
              destino: seg.arrival,
              origenCiudad: AIRPORT_CITY_MAP[seg.departure] || depPort.city_name || depPort.name || '',
              destinoCiudad: AIRPORT_CITY_MAP[seg.arrival] || arrPort.city_name || arrPort.name || '',
              salida: seg.departure_date,
              llegada: seg.arrival_date,
              vuelo: `${seg.marketing_company}${seg.transport_number}`,
              aerolinea: seg.marketing_company
            };
          }).filter(Boolean);

          itinerario.push({
            legId: jRef,
            origen: firstSeg.departure,
            destino: lastSeg.arrival,
            origenCiudad: AIRPORT_CITY_MAP[firstSeg.departure] || ports[firstSeg.departure]?.city_name || ports[firstSeg.departure]?.name || '',
            destinoCiudad: AIRPORT_CITY_MAP[lastSeg.arrival] || ports[lastSeg.arrival]?.city_name || ports[lastSeg.arrival]?.name || '',
            salida: firstSeg.departure_date,
            llegada: lastSeg.arrival_date,
            duracionMin: Math.round((journey.duration || 0) / 60),
            duracion: `${Math.floor((journey.duration||0)/3600)}h ${Math.round(((journey.duration||0)%3600)/60)}m`,
            escalas,
            ciudadesEscala,
            tripDays: 0,
            vuelo: `${firstSeg.marketing_company}${firstSeg.transport_number}`,
            segmentos
          });
          break; // Solo primer journey por association (ida o vuelta)
        }
      }

      // Price
      const price = sol.total_price || {};
      const precioUSD = price.total || 0;

      // Provider info
      const providerIds = (sol.providers || []).map(p => p.id);
      const providerName = providerIds.map(id => {
        const prov = providers[id];
        if (!prov) return id;
        if (prov.category === 'NDC') return `${prov.name || id} NDC`;
        return prov.name || prov.short_name || id;
      }).join('/');

      // GDS code mapping
      const gdsMap = { '1S': 'Sabre', '1A': 'Amadeus', '1G': 'Travelport' };
      const gdsLabel = providerIds.map(id => {
        if (gdsMap[id]) return gdsMap[id];
        const prov = providers[id];
        if (prov?.category === 'NDC') return `${id} NDC`;
        return prov?.name || id;
      }).join('/');

      // Airline
      const validating = assocs[0]?.validating_company || itinerario[0]?.vuelo?.substring(0,2) || '';
      const airlineName = companies[validating]?.name || validating;

      // Baggage from first association's first segment
      const firstSegRefs = Object.values(assocs[0]?.segment_references || {});
      const firstSeg = firstSegRefs[0] || {};
      const baggage = firstSeg.baggage || {};
      const cabinBag = firstSeg.cabin_baggage || {};
      const cabinInfo = firstSeg.cabin || {};

      const checkedQty = baggage.quantity || 0;
      const checkedUnit = baggage.unit || 'Units';
      const checkedIncluido = checkedQty > 0;
      const checkedLabel = checkedIncluido ? `${checkedQty}x 23KG` : 'No incluida';

      // Fare basis
      const fareBasis = firstSeg.fare_basis_code || '';
      const fareInfo = fares[Object.keys(fares).find(k => k.includes(fareBasis))] || {};

      return {
        id: `lleego_${sol.id}`,
        aerolinea: validating,
        aerolineaDesc: airlineName,
        precioUSD,
        monedaBase: price.currency || 'USD',
        expira: sol.time_limits?.last_ticket_date || null,
        itinerario,
        escalas: maxEscalas,
        equipaje: {
          handOn: { label: 'Incluida', incluido: true },
          carryOn: { label: cabinBag.included ? 'Incluido' : 'No incluido', incluido: !!cabinBag.included },
          checked: { label: checkedLabel, incluido: checkedIncluido }
        },
        source: 'GEA',
        fuente: 'GEA',
        gds: gdsLabel,
        fareType: fareInfo.fare_type || '',
        cabina: cabinInfo.short_name || cabinInfo.long_name || '',
        lleegoId: sol.id,
        lleegoSourceId: sol.source_id
      };
    } catch(e) {
      console.error('[Lleego] Error procesando solución:', e.message);
      return null;
    }
  }).filter(Boolean);
}

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
  const { tipo, origen, destino, salida, regreso, adultos, ninos, infantes, stops, tramos, moneda, airlines, cabinType, flightType } = req.body;
  
  // Lanzar búsqueda GLAS + Lleego en paralelo
  const glasPromise = (async () => {
    try {
      const token = await getToken();
      const stopsFilter = (stops !== undefined && stops !== '') ? parseInt(stops) : null;
      const currencyCode = moneda === 'ARS' ? null : 'USD';
      const airlinesArr = Array.isArray(airlines) && airlines.length ? airlines : [];
      const cabinVal = (cabinType !== undefined && cabinType !== null && cabinType !== '') ? cabinType : null;
      const flightTypeVal = (flightType !== undefined && flightType !== null && flightType !== '') ? flightType : null;

      let payload, endpoint, addSearchPayload;

      if (tipo === 'oneway') {
        endpoint = `${API_BASE}/FlightSearch/OnewayRemake`;
        payload = {
          DepartCode: origen, ArrivalCode: destino,
          DepartDate: `${salida}T00:00:00`, DepartTime: null,
          Adults: parseInt(adultos), Childs: parseInt(ninos), Infants: parseInt(infantes),
          CabinType: cabinVal, Stops: null, Airlines: airlinesArr,
          TypeOfFlightAllowedInItinerary: flightTypeVal, SortByGLASAlgorithm: "",
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
          CabinType: cabinVal, Stops: stopsFilter, Airlines: airlinesArr,
          TypeOfFlightAllowedInItinerary: flightTypeVal, SortByGLASAlgorithm: "",
          AlternateCurrencyCode: currencyCode, CorporationCodeGlas: null, IncludeFiltersOptions: true
        };
        addSearchPayload = { SearchTravelType: 1, OneWayModel: null, MultipleLegsModel: null, RoundTripModel: payload };
      } else if (tipo === 'multidestino') {
        endpoint = `${API_BASE}/FlightSearch/MultipleFlightsRemake`;
        const searchFlightLegs = tramos.map((t) => ({
          DepartCode: t.origen, ArrivalCode: t.destino,
          DepartDate: `${t.salida}T00:00:00`, DepartTime: null
        }));
        payload = {
          SearchFlightLegs: searchFlightLegs, Adults: parseInt(adultos), Childs: parseInt(ninos), Infants: parseInt(infantes),
          Stops: stopsFilter, Airlines: airlinesArr, CabinType: cabinVal,
          TypeOfFlightAllowedInItinerary: flightTypeVal, SortByGLASAlgorithm: null,
          AlternateCurrencyCode: currencyCode, CorporationCodeGlas: null, IncludeFiltersOptions: true
        };
        addSearchPayload = { SearchTravelType: 3, OneWayModel: null, MultipleLegsModel: payload, RoundTripModel: null };
      }

      await fetch(`${API_BASE}/FlightSearchHistory/AddSearch`, {
        method:'POST', headers: getHeaders(token), body: JSON.stringify(addSearchPayload)
      }).catch(()=>{});

      console.log(`[GLAS] Búsqueda: airlines=${airlinesArr.join(',')}, cabin=${cabinVal}, flightType=${flightTypeVal}, stops=${stopsFilter}`);
      const searchRes = await fetch(endpoint, {
        method:'POST', headers: getHeaders(token), body: JSON.stringify(payload)
      });
      if (!searchRes.ok) throw new Error(`API error: ${searchRes.status}`);
      const data = await searchRes.json();
      console.log(`[GLAS] ${data.minifiedQuotations?.length || 0} resultados`);
      
      const vuelos = procesarVuelos(data, stopsFilter);
      // Agregar fuente Tucano a cada resultado
      vuelos.forEach(v => { v.fuente = 'Tucano'; v.gds = v.source || ''; });
      return { vuelos, searchId: data.searchId || data.SearchId };
    } catch(err) {
      console.error('[GLAS] Error:', err.message);
      if (err.message.includes('401')) tokenCache = { token:null, expiry:0 };
      return { vuelos: [], searchId: null, error: err.message };
    }
  })();

  const lleegoPromise = buscarLleego({ tipo, origen, destino, salida, regreso, adultos, ninos, infantes, cabinType, stops, tramos });
  
  const sabrePromise = buscarSabre({ tipo, origen, destino, salida, regreso, adultos, ninos, infantes, cabinType, stops, tramos });

  // Esperar todos
  const [glasResult, lleegoVuelos, sabreVuelos] = await Promise.all([glasPromise, lleegoPromise, sabrePromise]);

  // Combinar resultados
  const todosVuelos = [...(glasResult.vuelos || []), ...(lleegoVuelos || []), ...(sabreVuelos || [])];
  todosVuelos.sort((a, b) => (a.precioTotal || a.precioUSD) - (b.precioTotal || b.precioUSD));

  const totalGlas = glasResult.vuelos?.length || 0;
  const totalLleego = lleegoVuelos?.length || 0;
  const totalSabre = sabreVuelos?.length || 0;
  console.log(`[Búsqueda] Total: ${todosVuelos.length} (Tucano: ${totalGlas}, GEA: ${totalLleego}, Sabre: ${totalSabre})`);

  if (!todosVuelos.length && glasResult.error) {
    return res.json({ ok: false, error: glasResult.error });
  }

  res.json({ ok: true, vuelos: todosVuelos, searchId: glasResult.searchId });
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

      // EQUIPAJE - En GLAS: chargeType 1 = incluido en tarifa, chargeType 0 = con cargo/no incluido
      // Además necesita pieces > 0 para estar realmente incluido

      // MOCHILA / ITEM PERSONAL → chargeType:1 siempre, pieces:1 siempre → incluida
      const handOnList = bagLeg?.handOn || [];
      const handOnIncluido = handOnList.some(b => b.chargeType === 1 && b.pieces >= 1);
      const handOnLabel = handOnIncluido ? 'Incluida' : (handOnList.length > 0 ? 'Con cargo' : 'No informado');

      // CARRY ON → chargeType:1 con pieces >= 1 = incluido
      const carryOnList = bagLeg?.carryOn || [];
      const carryOnItem = carryOnList.find(b => b.chargeType === 1 && b.pieces >= 1);
      const carryOnIncluido = !!carryOnItem;
      const carryOnLabel = carryOnItem 
        ? (`${carryOnItem.weight||''}${carryOnItem.weightUnit||''}`).trim() || 'Incluido' 
        : (carryOnList.length > 0 ? 'Con cargo' : 'No incluido');

      // CHECKED / DESPACHADO → chargeType:1 con pieces > 0 = incluido
      const checkedList = (bagLeg?.checked||[]).filter(b => b.passengerType === 0);
      const checkedItem = checkedList.find(b => b.chargeType === 1 && b.pieces > 0);
      const checkedIncluido = !!checkedItem;
      const checkedLabel = checkedItem 
        ? (checkedItem.weight && checkedItem.weight !== '0' && checkedItem.weight !== '' && checkedItem.weight !== null
            ? `${checkedItem.pieces}x ${checkedItem.weight}${checkedItem.unit || 'KG'}`
            : `${checkedItem.pieces}x 23KG`)
        : 'No incluida';

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
  
  // GEA: no availability check needed, solution is valid from search
  if (String(quotationId).startsWith('lleego_')) {
    return res.json({ ok: true, hasDifferences: false });
  }
  // Sabre: no availability check needed
  if (String(quotationId).startsWith('sabre_')) {
    return res.json({ ok: true, hasDifferences: false });
  }
  
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
  
  // ─── SABRE DIRECT booking ───
  if (String(quotationId).startsWith('sabre_')) {
    try {
      const cached = sabreSolutionsCache.get(quotationId);
      if (!cached) throw new Error('Solución Sabre expirada. Buscá de nuevo.');
      
      const token = await getSabreToken();
      if (!token) throw new Error('No se pudo autenticar con Sabre');
      
      // Build CreatePNR payload
      const segments = [];
      let segNum = 0;
      for (const leg of cached.legs) {
        for (const seg of leg.segmentos) {
          segNum++;
          const depDT = seg.salida; // "2026-05-02T08:00:00"
          segments.push({
            DepartureDateTime: depDT,
            FlightNumber: seg.vuelo.replace(/^[A-Z]{2}/, ''),
            NumberInParty: String(pasajeros.length),
            ResBookDesigCode: seg.cabina || 'Y',
            Status: 'NN',
            OriginLocation: { LocationCode: seg.origen },
            DestinationLocation: { LocationCode: seg.destino },
            MarketingAirline: { Code: seg.aerolinea, FlightNumber: seg.vuelo.replace(/^[A-Z]{2}/, '') }
          });
        }
      }
      
      // Build passenger info
      const paxInfo = pasajeros.map((p, idx) => {
        const paxData = {
          NameNumber: `${idx + 1}.1`,
          GivenName: p.nombre,
          Surname: p.apellido,
          DateOfBirth: `${p.nacimientoAnio}-${String(p.nacimientoMes).padStart(2,'0')}-${String(p.nacimientoDia).padStart(2,'0')}`,
          Gender: p.sexo === 'M' ? 'M' : 'F',
          PassengerType: p.tipo === 'INF' ? 'INF' : (p.tipo === 'CHD' ? 'CNN' : 'ADT'),
          NameReference: `P${idx + 1}`
        };
        return paxData;
      });
      
      // Contact info
      const holderPax = pasajeros[0] || {};
      const phone = contacto?.telefono || holderPax.telefono || '';
      const email = contacto?.email || holderPax.email || '';
      
      const createPNRBody = {
        CreatePassengerNameRecordRQ: {
          version: '2.4.0',
          TravelItineraryAddInfo: {
            AgencyInfo: { Ticketing: { TicketType: '7TAW' } },
            CustomerInfo: {
              ContactNumbers: {
                ContactNumber: [{ Phone: phone.replace(/\D/g, ''), PhoneUseType: 'H' }]
              },
              Email: [{ Address: email, Type: 'TO' }],
              PersonName: paxInfo.map(p => ({
                NameNumber: p.NameNumber,
                GivenName: p.GivenName,
                Surname: p.Surname
              }))
            }
          },
          AirBook: {
            OriginDestinationInformation: {
              FlightSegment: segments
            },
            HaltOnStatus: [{ Code: 'NN' }, { Code: 'NO' }, { Code: 'HL' }, { Code: 'UC' }]
          },
          AirPrice: [{
            PriceRequestInformation: {
              Retain: true,
              OptionalQualifiers: {
                PricingQualifiers: {
                  PassengerType: [...new Set(pasajeros.map(p => ({ Code: p.tipo === 'INF' ? 'INF' : (p.tipo === 'CHD' ? 'CNN' : 'ADT') })))]
                }
              }
            }
          }],
          PostProcessing: {
            EndTransaction: { Source: { ReceivedFrom: 'LUCKYTOUR COMPARADOR' } }
          }
        }
      };
      
      console.log('[Sabre] CreatePNR payload:', JSON.stringify(createPNRBody).substring(0, 1500));
      
      const bookRes = await fetch(`${SABRE_API_BASE}/v2.4.0/passenger/records?mode=create`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(createPNRBody)
      });
      
      const bookText = await bookRes.text();
      console.log(`[Sabre] CreatePNR response ${bookRes.status}:`, bookText.substring(0, 2000));
      
      if (!bookRes.ok) throw new Error(`Sabre booking error ${bookRes.status}: ${bookText.substring(0, 500)}`);
      
      const bookData = JSON.parse(bookText);
      const pnrData = bookData.CreatePassengerNameRecordRS || bookData;
      const pnr = pnrData.ItineraryRef?.ID || 
                   pnrData.AirBook?.OriginDestinationOption?.[0]?.FlightSegment?.[0]?.BookingLocator || '';
      
      console.log('[Sabre] PNR:', pnr);
      
      if (!pnr) throw new Error('No se obtuvo PNR de Sabre: ' + bookText.substring(0, 500));
      
      // Save to DB
      if (db) {
        try {
          await db.query(`INSERT INTO reservas (
            pnr,order_id,quotation_id,tipo_viaje,origen,destino,fecha_salida,
            aerolinea,precio_usd,moneda,adultos,ninos,infantes,estado,
            itinerario_json,pasajeros_json,contacto_json,notas,usuario_id,vendedor)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)`,
            [pnr, pnr, String(quotationId),
             vueloInfo?.tipo, vueloInfo?.origen, vueloInfo?.destino, vueloInfo?.salida,
             vueloInfo?.aerolinea, vueloInfo?.precioUSD, 'USD',
             pasajeros.filter(p=>p.tipo==='ADT').length,
             pasajeros.filter(p=>p.tipo==='CHD').length,
             pasajeros.filter(p=>p.tipo==='INF').length,
             'CREADA',
             JSON.stringify(vueloInfo?.itinerario),
             JSON.stringify(pasajeros),
             JSON.stringify(contacto),
             'Reserva Sabre Directo',
             req.user?.userId || null,
             req.user?.nombre || null]);
          console.log('[DB] Reserva Sabre guardada, PNR:', pnr);
        } catch(dbErr) { console.error('[DB] Error:', dbErr.message); }
      }
      
      return res.json({ ok: true, pnr, orderId: pnr, fuente: 'Sabre' });
    } catch(e) {
      console.error('[Sabre] Booking error:', e.message);
      return res.json({ ok: false, error: e.message });
    }
  }
  
  // ─── GEA / Lleego booking ───
  if (String(quotationId).startsWith('lleego_')) {
    try {
      const cached = lleegoSolutionsCache.get(quotationId);
      if (!cached) throw new Error('Solución GEA expirada. Buscá de nuevo.');
      
      const llToken = await getLleegoToken();
      if (!llToken) throw new Error('No se pudo autenticar con Lleego/GEA');
      
      const sol = cached.sol;
      const searchToken = cached.searchToken;
      const assocs = sol.data?.associations || [];
      
      // Build journey codes: airline + flightNum + dateYYYYMMDD
      const journeyCodes = [];
      for (const assoc of assocs) {
        const journeyRefs = assoc.journey_references || [];
        const jRef = journeyRefs[0]; if (!jRef) continue;
        const journey = cached.journeys[jRef]; if (!journey) continue;
        const firstSegId = (journey.segments || [])[0];
        const seg = cached.segments[firstSegId]; if (!seg) continue;
        const depDate = seg.departure_date ? seg.departure_date.substring(0, 10).replace(/-/g, '') : '';
        // Append origin+destination airport codes (required by Lleego NDC)
        const lastSegId = (journey.segments || []).slice(-1)[0];
        const lastSeg = cached.segments[lastSegId] || seg;
        const origen = seg.departure || '';
        const destino = lastSeg.arrival || '';
        journeyCodes.push(`${seg.marketing_company}${seg.transport_number}${depDate}${origen}${destino}`);
      }
      
      // Build travellers with birth_date and documents (required for NDC)
      const titleMap = { '0': 'Mr', '1': 'Mrs', 0: 'Mr', 1: 'Mrs' };
      const capitalizeWord = (s) => (s || '').split(' ').map(w => w.charAt(0).toUpperCase() + w.slice(1).toLowerCase()).join(' ');
      const travellers = pasajeros.map(p => {
        // Build birth_date from components
        let birthDate = null;
        if (p.fechaNacAnio && p.fechaNacMes && p.fechaNacDia) {
          birthDate = `${p.fechaNacAnio}-${String(p.fechaNacMes).padStart(2,'0')}-${String(p.fechaNacDia).padStart(2,'0')}`;
        }
        // Build documents array
        const docs = [];
        if (p.docNumero) {
          const docCode = (p.docTipo || '').toUpperCase();
          const llDocType = (docCode === 'PP' || docCode === 'PAS' || docCode === 'PASAPORTE') ? 'PP' : 'NI';
          docs.push({ type: llDocType, number: String(p.docNumero) });
        }
        const trav = {
          type: p.tipo || 'ADT',
          title: titleMap[p.genero] || 'Mr',
          name: capitalizeWord(p.nombre),
          surnames: [capitalizeWord(p.apellido)],
          documents: docs
        };
        if (birthDate) trav.birth_date = birthDate;
        return trav;
      });
      
      // Build fees
      const fees = pasajeros.map((p, i) => ({
        pax_type: `${p.tipo || 'ADT'}-${i}`,
        amount: 0
      }));
      
      // Holder = contacto (proper case, not uppercase)
      const holder = {
        name: capitalizeWord(contacto.nombre || pasajeros[0]?.nombre || ''),
        surnames: [capitalizeWord(contacto.apellido || pasajeros[0]?.apellido || '')],
        contact: {
          mails: [contacto.email || ''],
          phones: [
            { country_pref: '54', number: (contacto.telefono1 || '').replace(/[^\d]/g, '') },
            { country_pref: '54', number: (contacto.telefono2 || '').replace(/[^\d]/g, '') }
          ]
        },
        documents: []
      };
      
      const bookBody = {
        query: {
          token: searchToken,
          solutions: [{ id: sol.id, journeys: journeyCodes }],
          travellers,
          holder,
          fees
        }
      };
      
      console.log('[Lleego] Booking payload:', JSON.stringify(bookBody).substring(0, 800));
      
      // Call pricing endpoint BEFORE booking to validate/refresh NDC offer
      try {
        const _pjp = journeyCodes.map((j,i) => `&journey0${i}=${j}`).join('');
        const _purl = `https://api-tr.lleego.com/api/v2/transport/pricing?format=json&solutionID0=${sol.id}${_pjp}&extend=true&locale=es-ar`;
        console.log('[Lleego] Pre-booking pricing:', _purl);
        const _pr = await fetch(_purl, {
          headers: { 'Authorization': `Bearer ${llToken}`, 'x-api-key': LLEEGO_API_KEY, 'lang': 'es-ar' }
        });
        const _pd = await _pr.json();
        console.log('[Lleego] Pre-booking pricing status:', _pr.status, JSON.stringify(_pd).substring(0, 300));
        // Cache penalties from pricing if available
        const _pn = _pd.notes || _pd.data?.notes || [];
        if (_pn.length && quotationId) {
          const _pen = { cambio_antes: null, cambio_durante: null, devolucion_antes: null, devolucion_durante: null };
          for (const n of _pn) {
            const cat = (n.category || '').toLowerCase();
            const desc = (n.description || n.message || '').trim();
            const sn = (n.short_name || '');
            if (cat === 'refund' || cat.includes('refund')) {
              const na = desc.toLowerCase().includes('not allowed');
              if (sn.includes('Prior')||sn.includes('Before')) _pen.devolucion_antes = { permite: !na, monto: 0, moneda: 'USD', detalle: desc };
              if (sn.includes('After')) _pen.devolucion_durante = { permite: !na, monto: 0, moneda: 'USD', detalle: desc };
            }
            if (cat === 'change' || cat === 'changes') {
              const am = desc.match(/(\d+)\s*USD/i);
              const monto = am ? parseInt(am[1]) : 0;
              const na = desc.toLowerCase().includes('not allowed');
              if (sn.includes('Prior')||sn.includes('Before')) _pen.cambio_antes = { permite: !na, monto, moneda: 'USD', detalle: desc };
              if (sn.includes('After')) _pen.cambio_durante = { permite: !na, monto, moneda: 'USD', detalle: desc };
            }
          }
          penaltiesCache.set(quotationId, _pen);
          console.log('[Lleego] Cached penalties from pre-booking pricing');
        }
      } catch(_pe) {
        console.log('[Lleego] Pre-booking pricing error (continuing):', _pe.message);
      }
      
      const bookRes = await fetch('https://api-tr.lleego.com/api/v2/transport/booking?locale=es-ar', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${llToken}`,
          'Content-Type': 'application/json',
          'x-api-key': LLEEGO_API_KEY,
          'lang': 'es-ar'
        },
        body: JSON.stringify(bookBody)
      });
      
      const bookText = await bookRes.text();
      console.log(`[Lleego] Booking response ${bookRes.status}:`, bookText.substring(0, 500));
      
      if (!bookRes.ok) throw new Error(`Lleego booking error ${bookRes.status}: ${bookText.substring(0, 300)}`);
      
      let bookData;
      try { bookData = JSON.parse(bookText); } catch(e) { throw new Error('Respuesta inválida'); }
      
      // CHECK: Si Lleego devuelve success:false, la reserva falló
      if (bookData.success === false) {
        const errores = bookData.errors || [];
        const errMsg = errores.map(e => e.description || e.short_name || e.code || 'Error desconocido').join('; ');
        console.log('[Lleego] Booking FAILED:', errMsg);
        const esOfertaCaducada = errores.some(e => 
          (e.description && e.description.toLowerCase().includes('caducada')) ||
          (e.short_name && e.short_name.includes('900505')) ||
          (e.code === '75F')
        );
        if (esOfertaCaducada) {
          throw new Error('La oferta NDC ha caducado. Por favor, realizá una nueva búsqueda e intentá reservar más rápido. Las ofertas NDC tienen un tiempo de vigencia limitado.');
        }
        throw new Error(`Error en reserva GEA: ${errMsg}`);
      }
      
      // Log full response structure to find PNR and voucher ID
      console.log('[Lleego] Booking response keys:', Object.keys(bookData));
      if (bookData.booking) {
        console.log('[Lleego] booking keys:', Object.keys(bookData.booking));
        if (bookData.booking.lines?.[0]) console.log('[Lleego] line[0] keys:', Object.keys(bookData.booking.lines[0]));
      }
      console.log('[Lleego] Booking full:', JSON.stringify(bookData).substring(0, 2000));
      
      // Extract PNR from Lleego nested response - search multiple paths
      const line0 = bookData.booking?.lines?.[0] || {};
      const pnr = line0.booking_reference?.locator ||
                   line0.locator || line0.pnr || line0.record_locator ||
                   line0.booking_reference?.record_locator ||
                   bookData.locator || bookData.pnr || bookData.record_locator || 
                   bookData.data?.locator || bookData.booking?.locator ||
                   bookData.booking?.pnr || bookData.booking?.record_locator ||
                   // Deep search: look for any string that looks like a PNR (6 uppercase chars)
                   (() => {
                     const str = JSON.stringify(bookData);
                     const pnrMatch = str.match(/"(?:locator|pnr|record_locator|booking_reference)"\s*:\s*"([A-Z]{5,8})"/i);
                     if (pnrMatch) { console.log('[Lleego] PNR found via deep search:', pnrMatch[1]); return pnrMatch[1]; }
                     return null;
                   })() ||
                   'GEA-PENDING';
      // Try to find voucher/line ID for the Lleego web URL
      const lineId = bookData.booking?.lines?.[0]?.id || '';
      const bookingId = bookData.booking?.id || bookData.id || '';
      const orderId = lineId || bookingId || sol.id;
      
      console.log('[Lleego] Booking OK! PNR:', pnr, 'LineId:', lineId, 'BookingId:', bookingId, 'orderId:', orderId);
      
      // Guardar en DB
      if (db) {
        try {
          for (const p of pasajeros) {
            if (!p.docNumero) continue;
            const ex = await db.query('SELECT id FROM clientes WHERE doc_numero=$1', [p.docNumero]);
            if (ex.rows.length) {
              p._clienteId = ex.rows[0].id;
            } else {
              const ins = await db.query(`INSERT INTO clientes (apellido,nombre,email,genero,
                fecha_nac_dia,fecha_nac_mes,fecha_nac_anio,doc_tipo,doc_numero)
                VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING id`,
                [p.apellido,p.nombre,p.email,p.genero,p.fechaNacDia,p.fechaNacMes,p.fechaNacAnio,p.docTipo||'DNI',p.docNumero]);
              p._clienteId = ins.rows[0].id;
            }
          }
          
          await db.query(`INSERT INTO reservas (
            pnr,order_id,quotation_id,tipo_viaje,origen,destino,fecha_salida,
            aerolinea,precio_usd,moneda,adultos,ninos,infantes,estado,
            itinerario_json,pasajeros_json,contacto_json,notas,usuario_id,vendedor)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)`,
            [pnr, orderId, String(quotationId),
             vueloInfo?.tipo, vueloInfo?.origen, vueloInfo?.destino, vueloInfo?.salida,
             vueloInfo?.aerolinea, vueloInfo?.precioUSD, 'USD',
             pasajeros.filter(p=>p.tipo==='ADT').length,
             pasajeros.filter(p=>p.tipo==='CHD').length,
             pasajeros.filter(p=>p.tipo==='INF').length,
             'CREADA',
             JSON.stringify(vueloInfo?.itinerario),
             JSON.stringify(pasajeros),
             JSON.stringify(contacto),
             'Reserva GEA/Lleego',
             req.user?.userId || null,
             req.user?.nombre || null]);
          console.log('[DB] Reserva GEA guardada, PNR:', pnr);
          // Save cached penalties if available
          const cachedPenGEA = penaltiesCache.get(quotationId);
          if (cachedPenGEA) {
            try { await db.query('UPDATE reservas SET penalidades_json=$1 WHERE pnr=$2', [JSON.stringify(cachedPenGEA), pnr]); } catch(e) {}
          }
        } catch(dbErr) { console.error('[DB] Error:', dbErr.message); }
      }
      
      return res.json({ ok: true, pnr, orderNumber: orderId, orderId, fuente: 'GEA' });
    } catch(e) {
      console.error('[Lleego] Book error:', e.message);
      return res.json({ ok: false, error: e.message });
    }
  }
  
  // ─── GLAS / Tucano booking ───
  try {
    const token = await getToken();

    const ARG_ID = '3144952d-b7f4-4ddf-9ed8-8021bfc67c4b';
    function sv(v) { return (v && v !== 'undefined') ? v : null; }
    
    // Sanitizar pasajeros — asegurar campos mínimos
    for (const p of pasajeros) {
      if (!p.apellido) p.apellido = '';
      if (!p.nombre) p.nombre = '';
      if (!p.genero && p.genero !== 0 && p.genero !== '0') p.genero = '0';
      if (!p.fechaNacDia) p.fechaNacDia = '1';
      if (!p.fechaNacMes) p.fechaNacMes = '1';
      if (!p.fechaNacAnio) p.fechaNacAnio = '2025';
      if (!sv(p.nacionalidadId)) p.nacionalidadId = ARG_ID;
      if (!sv(p.docPaisId)) p.docPaisId = ARG_ID;
      if (!sv(p.factPaisId)) p.factPaisId = ARG_ID;
      if (!sv(p.docTipoId)) p.docTipoId = 'f0914e0e-b105-4805-a118-1ac3f497eff5'; // DNI
      if (!sv(p.factTipoId)) p.factTipoId = '695a576b-23b3-460a-98f3-7a2916ddeed9'; // CUIL
    }
    
    function buildPax(p, i, tipo) {
      const typeNum = tipo==='ADT'?0:tipo==='CHD'?1:2;
      // SCIWeb usa CNN para children, no CHD
      const keyPrefix = tipo==='CHD' ? 'CNN' : tipo;
      return {
        key: `${keyPrefix}${i+1}`, indexUI: i+1, passengerType: typeNum,
        FirstName: p.nombre.toUpperCase(), LastName: p.apellido.toUpperCase(),
        Gender: parseInt(p.genero),
        BirthdateDay: parseInt(p.fechaNacDia), BirthdateMonth: parseInt(p.fechaNacMes), BirthdateYear: parseInt(p.fechaNacAnio),
        Email: p.email || null,
        DocumentType: sv(p.docTipoId), DocumentCountry: sv(p.docPaisId) || ARG_ID, DocumentNumber: p.docNumero,
        ExpirationdateDay: parseInt(p.docVencDia), ExpirationdateMonth: parseInt(p.docVencMes), ExpirationdateYear: parseInt(p.docVencAnio),
        Nationality: sv(p.nacionalidadId) || ARG_ID,
        AccountingDocumentType: sv(p.factTipoId) || null,
        AccountingDocumentCountry: sv(p.factPaisId) || null,
        AccountingDocumentNumber: sv(p.factNumero) || null,
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
          itinerario_json,pasajeros_json,contacto_json,usuario_id,vendedor)
          VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22)
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
           JSON.stringify(contacto),
           req.user?.userId || null,
           req.user?.nombre || null]);

        for (const p of pasajeros) {
          if (p._clienteId) {
            await db.query('INSERT INTO reserva_pasajeros (reserva_id,cliente_id,tipo,apellido,nombre,email) VALUES ($1,$2,$3,$4,$5,$6)',
              [resIns.rows[0].id, p._clienteId, p.tipo, p.apellido, p.nombre, p.email]);
          }
        }
        console.log('[DB] Reserva guardada, PNR:', data.recordLocator);
          // Save cached penalties if available
          const cachedPenTuc = penaltiesCache.get(quotationId);
          if (cachedPenTuc) {
            try { await db.query('UPDATE reservas SET penalidades_json=$1 WHERE pnr=$2', [JSON.stringify(cachedPenTuc), data.recordLocator]); } catch(e) {}
          }
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
    // Vendedores solo ven sus reservas, admin ve todas
    if (req.user && req.user.rol !== 'admin') {
      params.push(req.user.userId);
      where.push(`usuario_id=$${params.length}`);
    }
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
    const estados = ['CREADA', 'EMITIDA', 'CANCELADA'];
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
    
    // 400 con "no cuenta con vuelos asociados" = reserva cancelada/expirada
    if (!resp.ok) {
      let errorData = {};
      try { errorData = JSON.parse(text); } catch(e) {}
      const innerMsg = errorData?.innerException?.message || errorData?.message || '';
      
      if (innerMsg.includes('no cuenta con vuelos') || innerMsg.includes('no ha sido posible cargar')) {
        // Reserva cancelada/expirada en la aerolínea
        const apiEstado = 'CANCELADA';
        let estadoActualizado = false;
        if (reserva.estado !== apiEstado) {
          await db.query('UPDATE reservas SET estado=$1, updated_at=NOW() WHERE id=$2', [apiEstado, req.params.id]);
          estadoActualizado = true;
        }
        return res.json({
          ok: true,
          estadoAPI: apiEstado,
          estadoAnterior: reserva.estado,
          estadoActualizado,
          pnr: reserva.pnr,
          tickets: [],
          vuelos: [],
          pasajeros: [],
          mensaje: 'La reserva ya no tiene vuelos asociados (cancelada/expirada)'
        });
      }
      
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

    // Log completo de tickets y orderState
    console.log(`[Verificar] orderState: ${orderState}, ticketsInformation count: ${(data.ticketsInformation || []).length}`);
    console.log(`[Verificar] ticketsInformation raw:`, JSON.stringify(data.ticketsInformation || []).substring(0, 500));
    console.log(`[Verificar] passengersInformation tickets:`, JSON.stringify((data.passengersInformation || []).map(p => ({ name: p.lastName, tickets: p.tickets }))).substring(0, 500));

    // Tickets - mapear estados
    // E = Emitido activo, A = Anulado/VOID, R = Reembolsado, V = Void
    const tickets = (data.ticketsInformation || []).map(t => ({
      numero: t.number,
      carrier: t.validatigCarrierNumericCode || t.validatingCarrierNumericCode,
      status: t.status,
      statusDesc: t.statusDescription || t.statusName || null
    }));
    const ticketsEmitidos = tickets.filter(t => t.status === 'E' || t.status === 'Emitido' || t.status === 'ISSUED');
    const ticketsVoid = tickets.filter(t => t.status === 'A' || t.status === 'V' || t.status === 'VOID');
    console.log(`[Verificar] Tickets: total=${tickets.length} emitidos=${ticketsEmitidos.length} void=${ticketsVoid.length}`, JSON.stringify(tickets));

    // Estado de vuelos
    const vuelos = (data.flightsInformation || []).map(f => ({
      vuelo: f.flightNumber,
      ruta: `${f.departureAirportCode} → ${f.arrivalAirportCode}`,
      status: f.status
    }));
    const vuelosCancelados = vuelos.filter(v => v.status === 'XX' || v.status === 'UC' || v.status === 'UN');

    // Pasajeros con tickets
    const pasajeros = (data.passengersInformation || []).map(p => ({
      nombre: `${p.lastName}, ${p.firstName}`,
      tipo: p.typeCode,
      ticketStatus: p.tickets?.[0]?.status || null,
      ticketNumber: p.tickets?.[0]?.number || null
    }));

    // Determinar estado
    let apiEstado = null;
    if (vuelosCancelados.length === vuelos.length && vuelos.length > 0) {
      apiEstado = 'CANCELADA';
    } else if (ticketsEmitidos.length > 0) {
      // Hay tickets activos emitidos
      apiEstado = 'EMITIDA';
    } else if (ticketsVoid.length > 0 && ticketsEmitidos.length === 0) {
      // Todos los tickets fueron voideados → cancelada
      apiEstado = 'CANCELADA';
    } else if (vuelos.some(v => v.status === 'OK' || v.status === 'HK')) {
      apiEstado = 'CREADA';
    } else {
      apiEstado = 'CREADA';
    }
    console.log(`[Verificar] Estado: ${apiEstado} (orderState=${orderState}, emitidos=${ticketsEmitidos.length}, void=${ticketsVoid.length})`);

    // Actualizar en DB si cambió
    let estadoActualizado = false;
    if (apiEstado && apiEstado !== reserva.estado) {
      await db.query('UPDATE reservas SET estado=$1, updated_at=NOW() WHERE id=$2', [apiEstado, req.params.id]);
      estadoActualizado = true;
    }

    // Si se detectó emisión activa, guardar datos
    if (apiEstado === 'EMITIDA' && !reserva.emision_data) {
      const emisionData = {
        tickets: ticketsEmitidos,
        vuelos,
        pasajeros,
        emitidoEn: new Date().toISOString(),
        orderState
      };
      await db.query('UPDATE reservas SET emision_data=$1 WHERE id=$2', [JSON.stringify(emisionData), req.params.id]);
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
      ticketsVoid: ticketsVoid.map(t => `${t.carrier}-${t.numero} (VOID)`),
      allTickets: tickets,
      vuelos,
      pasajeros
    });
  } catch(e) {
    console.error('[Verificar] Error:', e.message);
    res.json({ ok: false, error: e.message });
  }
});

// ─── RECOTIZAR RESERVA (RetrievePricing) ───
app.post('/reservas/:id/recotizar', async (req, res) => {
  if (!db) return res.json({ ok: false, error: 'Sin DB' });
  try {
    const r = await db.query('SELECT * FROM reservas WHERE id=$1', [req.params.id]);
    if (!r.rows.length) return res.json({ ok: false, error: 'Reserva no encontrada' });
    const reserva = r.rows[0];
    if (!reserva.order_id) return res.json({ ok: false, error: 'Sin orderId' });

    const token = await getToken();
    const hdrs = getHeaders(token);

    // Calificadores opcionales del frontend
    const { moneda, fareType, nationality, overrideCarrier, brandId } = req.body || {};

    // Paso 1: RetrieveReservation para obtener datos actuales
    const rrResp = await fetch(`${API_BASE}/FlightReservation/RetrieveReservation`, {
      method: 'POST', headers: hdrs,
      body: JSON.stringify({ OrderId: reserva.order_id })
    });
    if (!rrResp.ok) return res.json({ ok: false, error: 'No se pudo cargar la reserva' });
    const rrData = JSON.parse(await rrResp.text());

    const flights = rrData.flightsInformation || [];
    const passengers = rrData.passengersInformation || [];
    if (!flights.length) return res.json({ ok: false, error: 'Sin vuelos en la reserva' });

    // Construir segmentos
    const segments = flights.map((f, i) => ({
      ReferenceId: String(i + 1),
      NumberInPNR: f.numberInPNR || null,
      MarketingCarrier: f.marketingAirlineCode || f.airlineCode,
      OperatingCarrier: f.operatingAirlineCode || f.airlineCode,
      Departure: f.departureAirportCode,
      Arrival: f.arrivalAirportCode,
      DepartureDate: f.departureDate,
      ArrivalDate: f.arrivalDate,
      FlightNumber: (f.flightNumber || '').replace(/^[A-Z]{2}\s*/, ''),
      BookingClass: f.bookingClass || '',
      BrandId: brandId || '',
      Grp: null
    }));

    // Construir pasajeros con referenceId del PNR
    const typeMap = { 0: 'ADT', 1: 'CNN', 2: 'INF' };
    const paxWithType = passengers.map(p => ({
      ReferenceId: p.referenceId || p.reference,
      Type: typeMap[p.type] || p.typeCode || 'ADT',
      DiscountType: typeMap[p.type] || p.typeCode || 'ADT'
    }));
    const paxRefIds = paxWithType.map(p => p.ReferenceId);
    const segRefIds = segments.map(s => s.ReferenceId);

    // Payload para RetrievePricing
    const pricingPayload = {
      OrderId: reserva.order_id,
      OrderRecord: null,
      Source: 0,
      StrategyType: 0,
      FareType: fareType || 0,
      Currency: moneda || null,
      Nationality: nationality || null,
      OverrideValidatingCarrier: overrideCarrier || null,
      Office: null,
      ACCodes: null,
      CorporateCodeGlas: null,
      ExcemptTaxes: '',
      AdditionalData: {},
      PassengerReferenceIds: paxRefIds,
      PassengersWithType: paxWithType,
      SegmentReferenceIds: segRefIds,
      Segments: segments
    };

    console.log('[Recotizar] Payload:', JSON.stringify(pricingPayload).substring(0, 500));

    // Intentar pricing — si falla con INF, reintentar sin ellos
    let prResp, prText, prSuccess = false;
    const hasInfants = paxWithType.some(p => p.Type === 'INF');
    
    for (const excludeInf of [false, ...(hasInfants ? [true] : [])]) {
      const currentPax = excludeInf 
        ? paxWithType.filter(p => p.Type !== 'INF')
        : paxWithType;
      const currentRefIds = currentPax.map(p => p.ReferenceId);
      
      const currentPayload = { ...pricingPayload, PassengerReferenceIds: currentRefIds, PassengersWithType: currentPax };
      
      if (excludeInf) console.log('[Recotizar] Reintentando SIN infantes');
      
      for (const ep of [
        `${API_BASE}/FlightReservationPricing/RetrievePricing`,
        `${API_BASE}/FlightReservationPricing/RetrievePricingByText`
      ]) {
        console.log(`[Recotizar] Intentando ${ep}`);
        prResp = await fetch(ep, {
          method: 'POST', headers: hdrs,
          body: JSON.stringify(currentPayload)
        });
        prText = await prResp.text();
        console.log(`[Recotizar] HTTP ${prResp.status}, body: ${prText.substring(0, 300)}`);
        if (prResp.ok && prText.length > 5) { prSuccess = true; break; }
      }
      if (prSuccess) break;
    }

    if (!prSuccess) {
      return res.json({ ok: false, error: `Ningún endpoint respondió. Último: HTTP ${prResp.status}. Response: ${prText.substring(0, 200)}` });
    }

    let prData;
    try { prData = JSON.parse(prText); } catch(e) {
      return res.json({ ok: false, error: 'Respuesta inválida' });
    }

    // Extraer precios de la respuesta
    const tarifas = [];
    const fares = prData.storedFares || prData.fares || prData.pricingOptions || prData.quotations || [];
    if (Array.isArray(fares)) {
      for (const fare of fares) {
        console.log('[Recotizar] Fare keys:', Object.keys(fare).join(','), 'passengerDiscountType:', fare.passengerDiscountType);
        console.log('[Recotizar] Commission:', JSON.stringify(fare.commissionRule));
        console.log('[Recotizar] OverComm:', JSON.stringify(fare.overCommissionRule));
        const fv = fare.fareValues || fare;
        tarifas.push({
          pasajero: fare.compiledPassenger || fare.compiledPassengerList?.[0] || '',
          tipo: fare.passengerDiscountType || fare.passengerTypeCode || fare.typeCode || 'ADT',
          tipoTarifa: fare.fareType || '',
          validadora: fare.validatingCarrier || '',
          tarifaBase: fv.baseFareAmount || fv.fareAmount || 0,
          monedaBase: fv.baseFareCurrency || fv.fareCurrency || 'USD',
          equivalente: fv.equivalentFareAmount || null,
          monedaEquivalente: fv.equivalentFareCurrency || null,
          impuestos: fv.totalTaxAmount || fv.taxAmount || 0,
          monedaImpuestos: fv.totalTaxCurrency || 'USD',
          total: fv.totalAmount || fv.total || 0,
          monedaTotal: fv.totalCurrency || 'USD',
          glasTotal: fv.totalGLASAmount || fv.totalAmount || 0,
          monedaGlas: fv.totalGLASCurrency || fv.totalCurrency || 'USD',
          fee: (fare.feeValues || []).reduce((s, f) => s + (f.amount || 0), 0),
          monedaFee: (fare.feeValues || [])[0]?.currency || 'USD',
          feeDetail: (fare.feeValues || []).map(f => ({ amount: f.amount, currency: f.currency, rule: f.ruleId })),
          comisionObtenida: fare.commissionRule?.obtained || null,
          comisionCedida: fare.commissionRule?.ceded || null,
          overComision: fare.overCommissionRule || null,
          sellingAmount: fare.sellingFareValues?.sellingPriceAmount || 0,
          sellingCurrency: fare.sellingFareValues?.sellingPriceCurrency || ''
        });
      }
    }

    // Extraer PricingId para SavePricing
    const pricingId = prData.pricingId || prData.PricingId || prData.id || null;
    console.log('[Recotizar] PricingId:', pricingId, 'Keys:', Object.keys(prData).join(','));
    if (!pricingId) console.log('[Recotizar] Full response keys search:', JSON.stringify(prData).substring(0, 500));
    const segRefIdsForSave = segments.map((s, i) => String(i + 1));

    // Extraer penalidades - buscar en pricing response, reserva, y dentro de los fares
    const prPenalties = prData.penalties || prData.penaltiesInformation || [];
    const rrPenalties = rrData.penaltiesInformation || rrData.penalties || [];
    let allPenalties = prPenalties.length ? prPenalties : rrPenalties;
    
    // Si no hay penalties a nivel root, buscar en los fares
    if (!allPenalties.length && fares.length && fares[0].rules) {
      console.log('[Recotizar] Buscando penalties en fare.rules:', JSON.stringify(fares[0].rules).substring(0, 500));
      // rules puede tener penalties como sub-array o ser las penalties mismas
      const fareRules = fares[0].rules;
      if (Array.isArray(fareRules)) {
        allPenalties = fareRules.filter(r => r.type === 0 || r.type === 1 || (r.penaltyType !== undefined));
      }
    }
    
    // También buscar en storedFares del pricing
    if (!allPenalties.length) {
      const storedF = prData.storedFares || [];
      if (storedF.length && storedF[0].penalties) {
        allPenalties = storedF[0].penalties;
      }
    }
    
    console.log('[Recotizar] Penalties count:', allPenalties.length, allPenalties.length ? JSON.stringify(allPenalties).substring(0, 300) : 'none');
    
    let penalidades = null;
    if (allPenalties.length) {
      const extractPen = (type, applicability) => {
        const p = allPenalties.find(pen => pen.type === type && pen.applicability === applicability);
        if (!p) {
          // Fallback: buscar solo por type sin applicability
          if (applicability === 0) {
            const fb = allPenalties.find(pen => pen.type === type) || allPenalties.find(pen => (pen.penaltyType || '').toString().toLowerCase().includes(type === 0 ? 'chang' : 'cancel'));
            if (fb) return { monto: fb.amount || fb.penaltyAmount || 0, moneda: fb.currency || fb.penaltyCurrency || 'USD', permite: !!fb.enabled };
          }
          return null;
        }
        return { monto: p.amount || p.penaltyAmount || 0, moneda: p.currency || p.penaltyCurrency || 'USD', permite: !!p.enabled };
      };
      penalidades = {
        cambio_antes: extractPen(0, 0),
        cambio_durante: extractPen(0, 1),
        devolucion_antes: extractPen(1, 0),
        devolucion_durante: extractPen(1, 1),
        // Compatibilidad
        cambio: extractPen(0, 0),
        cancelacion: extractPen(1, 0)
      };
    }
    console.log('[Recotizar] Penalties found:', JSON.stringify(penalidades));

    // Save penalties to DB for PDF use
    if (penalidades) {
      try {
        await db.query('UPDATE reservas SET penalidades_json=$1, updated_at=NOW() WHERE id=$2', [JSON.stringify(penalidades), req.params.id]);
        console.log('[Recotizar] Penalties saved to DB');
      } catch(e) { console.log('[Recotizar] Error saving penalties:', e.message); }
    }

    // Extract brand info from flights
    const brands = [...new Set(flights.map(f => f.brandName).filter(Boolean))];
    const brandLabel = brands.join(' / ') || null;

    res.json({
      ok: true,
      pnr: rrData.recordLocator,
      tarifas,
      pricingId,
      penalidades,
      brand: brandLabel,
      orderId: reserva.order_id,
      segmentIds: segRefIdsForSave,
      rawKeys: Object.keys(prData),
      rawPreview: JSON.stringify(prData).substring(0, 800)
    });
  } catch(e) {
    console.error('[Recotizar] Error:', e.message);
    res.json({ ok: false, error: e.message });
  }
});

// ─── GUARDAR TARIFA (SavePricing) ───
app.post('/reservas/:id/guardar-tarifa', async (req, res) => {
  if (!db) return res.json({ ok: false, error: 'Sin DB' });
  try {
    const r = await db.query('SELECT * FROM reservas WHERE id=$1', [req.params.id]);
    if (!r.rows.length) return res.json({ ok: false, error: 'Reserva no encontrada' });
    const reserva = r.rows[0];

    const { pricingId, segmentIds, overrideVC, netoTotal, moneda } = req.body;
    if (!pricingId) return res.json({ ok: false, error: 'Sin PricingId - cotizá primero' });

    const token = await getToken();
    const hdrs = getHeaders(token);

    const savePayload = {
      OrderId: reserva.order_id,
      PricingId: pricingId,
      FaresNumberInPNR: ["0"],
      OverrideVC: overrideVC || null,
      SegmentsReferenceIds: segmentIds || ["1", "2"]
    };

    console.log('[SavePricing] Payload:', JSON.stringify(savePayload));

    const resp = await fetch(`${API_BASE}/FlightReservationPricing/SavePricing`, {
      method: 'POST', headers: hdrs,
      body: JSON.stringify(savePayload)
    });
    const text = await resp.text();
    console.log('[SavePricing] HTTP', resp.status, 'Response:', text.substring(0, 500));

    if (!resp.ok) {
      return res.json({ ok: false, error: `API respondió ${resp.status}: ${text.substring(0, 200)}` });
    }

    // Actualizar precio en DB local
    if (netoTotal) {
      await db.query('UPDATE reservas SET precio_usd=$1, precio_venta_usd=$2, updated_at=NOW() WHERE id=$3', [netoTotal, netoTotal, req.params.id]);
      console.log('[SavePricing] DB actualizada con neto:', netoTotal);
    }

    res.json({ ok: true, mensaje: 'Tarifa guardada exitosamente. Precio actualizado.' });
  } catch(e) {
    console.error('[SavePricing] Error:', e.message);
    res.json({ ok: false, error: e.message });
  }
});

// ─── EMITIR TICKETS ───
// La emisión se hace desde SCIWeb. Este endpoint abre el link o marca manualmente.
app.post('/reservas/:id/emitir', async (req, res) => {
  if (!db) return res.json({ ok: false, error: 'Sin DB' });
  try {
    const r = await db.query('SELECT * FROM reservas WHERE id=$1', [req.params.id]);
    if (!r.rows.length) return res.json({ ok: false, error: 'Reserva no encontrada' });
    const reserva = r.rows[0];
    if (!reserva.order_id) return res.json({ ok: false, error: 'Sin orderId' });

    // Sabre Direct: emit via Sabre API
    const isSabre = (reserva.quotation_id || '').startsWith('sabre_') || (reserva.notas || '').includes('Sabre');
    if (isSabre) {
      try {
        const sabreToken = await getSabreToken();
        if (!sabreToken) throw new Error('No se pudo autenticar con Sabre');
        
        // Issue ticket via Sabre REST
        const ticketBody = {
          AirTicketRQ: {
            version: '1.2.1',
            DesignatePrinter: {
              Printers: { Ticket: { CountryCode: 'AR' } }
            },
            Itinerary: { ID: reserva.pnr },
            Ticketing: [{
              FOP_Qualifiers: {
                BasicFOP: { Type: 'CA' }
              },
              MiscQualifiers: {
                Ticket: { Type: 'ETR' }
              }
            }],
            PostProcessing: {
              EndTransaction: { Source: { ReceivedFrom: 'LUCKYTOUR' } }
            }
          }
        };
        
        console.log('[Sabre] Ticketing PNR:', reserva.pnr);
        const ticketRes = await fetch(`${SABRE_API_BASE}/v1.2.1/air/ticket?mode=create`, {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${sabreToken}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify(ticketBody)
        });
        const ticketText = await ticketRes.text();
        console.log(`[Sabre] Ticketing response ${ticketRes.status}:`, ticketText.substring(0, 1000));
        
        if (ticketRes.ok) {
          await db.query("UPDATE reservas SET estado='EMITIDA' WHERE id=$1", [reserva.id]);
          return res.json({ ok: true, emitida: true, pnr: reserva.pnr, fuente: 'Sabre' });
        } else {
          let errMsg = `Error ${ticketRes.status}`;
          try { const errData = JSON.parse(ticketText); errMsg = errData.message || errMsg; } catch(e) {}
          return res.json({ ok: false, error: `Sabre: ${errMsg}` });
        }
      } catch(e) {
        console.error('[Sabre] Ticketing error:', e.message);
        return res.json({ ok: false, error: e.message });
      }
    }

    // GEA: emit via Lleego API
    const isGEA = (reserva.quotation_id || '').startsWith('lleego_') || (reserva.notas || '').includes('GEA');
    if (isGEA) {
      try {
        const llToken = await getLleegoToken();
        if (!llToken) throw new Error('No se pudo autenticar con Lleego');
        
        // Emit via PUT /api/v2/transport/emit/{lineId}?locator={PNR}&locale=es-ar
        const lineId = reserva.order_id; // We store lineId as order_id
        const emitUrl = `https://api-tr.lleego.com/api/v2/transport/emit/${lineId}?locator=${reserva.pnr}&locale=es-ar`;
        console.log('[Lleego] Emitting:', emitUrl);
        
        const emitRes = await fetch(emitUrl, {
          method: 'PUT',
          headers: {
            'Authorization': `Bearer ${llToken}`,
            'Content-Type': 'application/json',
            'x-api-key': LLEEGO_API_KEY,
            'lang': 'es-ar'
          }
        });
        const emitText = await emitRes.text();
        console.log(`[Lleego] Emit response ${emitRes.status}:`, emitText.substring(0, 1000));
        
        if (emitRes.ok) {
          await db.query("UPDATE reservas SET estado='EMITIDA' WHERE id=$1", [reserva.id]);
          return res.json({ ok: true, emitida: true, pnr: reserva.pnr, fuente: 'GEA' });
        } else {
          // Parse error message
          let errMsg = `Error ${emitRes.status}`;
          try { const errData = JSON.parse(emitText); errMsg = errData.errors?.[0]?.message || errData.message || errMsg; } catch(e) {}
          return res.json({ ok: false, error: `Lleego: ${errMsg}` });
        }
      } catch(e) {
        console.error('[Lleego] Emit error:', e.message);
        return res.json({ ok: false, error: e.message });
      }
    }

    // Tucano: SCIWeb ticketing
    const sciweb_url = `https://sciweb.tucanotours.com.ar/FlightOrders/Ticketing/${reserva.order_id}`;
    res.json({ ok: true, sciweb_url, order_id: reserva.order_id, pnr: reserva.pnr });
  } catch(e) {
    console.error('[Emitir] Error:', e.message);
    res.json({ ok: false, error: e.message });
  }
});

// ─── GENERAR PDF DE RESERVA ───
app.post('/reservas/:id/pdf', async (req, res) => {
  if (!db) return res.json({ ok: false, error: 'Sin DB' });
  try {
    const r = await db.query(`
      SELECT r.*, 
        json_agg(json_build_object(
          'nombre', c.apellido || ', ' || c.nombre,
          'tipo', rp.tipo,
          'doc_tipo', c.doc_tipo,
          'doc_numero', c.doc_numero
        )) as pasajeros_info
      FROM reservas r
      LEFT JOIN reserva_pasajeros rp ON rp.reserva_id = r.id
      LEFT JOIN clientes c ON c.id = rp.cliente_id
      WHERE r.id = $1
      GROUP BY r.id
    `, [req.params.id]);
    if (!r.rows.length) return res.json({ ok: false, error: 'Reserva no encontrada' });
    const reserva = r.rows[0];

    // Obtener datos frescos de la API
    let vuelos = [], airportsInfo = {}, aerolinea = reserva.aerolinea || '';
    let fareInfo = null;
    let penalidades = null;
    const isGEA = (reserva.quotation_id || '').startsWith('lleego_') || (reserva.notas || '').includes('GEA');
    const isSabre = (reserva.quotation_id || '').startsWith('sabre_') || (reserva.notas || '').includes('Sabre');

    if (reserva.order_id && !isGEA && !isSabre) {
      try {
        const token = await getToken();
        const hdrs = getHeaders(token);
        const rrResp = await fetch(`${API_BASE}/FlightReservation/RetrieveReservation`, {
          method: 'POST', headers: hdrs,
          body: JSON.stringify({ OrderId: reserva.order_id })
        });
        if (rrResp.ok) {
          const rrData = JSON.parse(await rrResp.text());
          console.log('[PDF] RetrieveReservation keys:', Object.keys(rrData).join(','));
          vuelos = rrData.flightsInformation || [];
          airportsInfo = rrData.airportsInformation || {};
          if (vuelos.length && vuelos[0].airlineName) aerolinea = vuelos[0].airlineName;
          
          // Extraer penalidades si las hay
          const rrPenalties = rrData.penaltiesInformation || rrData.penalties || [];
          console.log(`[PDF] Penalty keys in rrData:`, Object.keys(rrData).filter(k => k.toLowerCase().includes('penal') || k.toLowerCase().includes('rule')).join(','));
          console.log(`[PDF] Penalties raw count: ${rrPenalties.length}`, rrPenalties.length ? JSON.stringify(rrPenalties).substring(0, 300) : 'none');
          if (rrPenalties.length) {
            const extractPen = (type, applicability) => {
              const p = rrPenalties.find(pen => pen.type === type && pen.applicability === applicability);
              if (!p) {
                if (applicability === 0) {
                  const fb = rrPenalties.find(pen => pen.type === type) || rrPenalties.find(pen => (pen.penaltyType || '').toString().toLowerCase().includes(type === 0 ? 'chang' : 'cancel'));
                  if (fb) return { monto: fb.amount || fb.penaltyAmount || 0, moneda: fb.currency || fb.penaltyCurrency || 'USD', permite: !!fb.enabled };
                }
                return null;
              }
              return { monto: p.amount || p.penaltyAmount || 0, moneda: p.currency || p.penaltyCurrency || 'USD', permite: !!p.enabled };
            };
            penalidades = {
              cambio_antes: extractPen(0, 0),
              cambio_durante: extractPen(0, 1),
              devolucion_antes: extractPen(1, 0),
              devolucion_durante: extractPen(1, 1),
              cambio: extractPen(0, 0),
              cancelacion: extractPen(1, 0)
            };
          }
          // También chequear fareRulesInformation
          if (!penalidades && rrData.fareRulesInformation) {
            console.log('[PDF] fareRulesInformation encontrado, keys:', Object.keys(rrData.fareRulesInformation).join(','));
          }
          // Puede haber múltiples storedFares (vieja + nueva por SavePricing)
          // Agrupar por numberInPNR y tomar el grupo más alto (más reciente)
          const storedFares = rrData.storedFaresInformation || [];
          console.log('[PDF] storedFares count:', storedFares.length);
          storedFares.forEach((f, idx) => {
            const total = f.fareValues?.totalAmount || 0;
            const fee = (f.feeValues||[]).reduce((s,x)=>s+(x.amount||0),0);
            // Log all keys to find correct passenger type field
            const topKeys = Object.keys(f).filter(k => typeof f[k] !== 'object' || f[k] === null);
            console.log(`[PDF] fare[${idx}]: total=${total}, fee=${fee}, keys=${topKeys.join(',')}, vals=${topKeys.map(k=>k+'='+f[k]).join(', ')}`);
          });
          
          // Tomar todas las tarifas del numberInPNR más alto
          let latestFares = storedFares;
          if (storedFares.length > 0) {
            const maxNum = Math.max(...storedFares.map(f => parseInt(f.numberInPNR) || 0));
            const latestGroup = storedFares.filter(f => (parseInt(f.numberInPNR) || 0) === maxNum);
            if (latestGroup.length > 0) latestFares = latestGroup;
          }
          
          // passengersInformation tiene el tipo de cada pasajero
          const paxInfo = rrData.passengersInformation || [];
          const pTypeMap = { 0: 'ADT', 1: 'CHD', 2: 'INF' };
          console.log(`[PDF] passengersInfo: count=${paxInfo.length}, types=[${paxInfo.map(p => `${p.type}=${pTypeMap[p.type]}`).join(',')}]`);
          
          fareInfo = latestFares.map((f, idx) => {
            const totalTarifa = f.fareValues?.totalAmount || 0;
            const feeTucano = (f.feeValues || []).reduce((s, fee) => s + (fee.amount || 0), 0);
            // Use fare's own passengerType field first, then fallback to passengersInformation
            let paxType = 'ADT';
            if (f.passengerType !== undefined) {
              paxType = pTypeMap[f.passengerType] || 'ADT';
            } else if (paxInfo[idx]) {
              paxType = pTypeMap[paxInfo[idx].type] || paxInfo[idx].typeCode || 'ADT';
            }
            console.log(`[PDF] fare[${idx}]: paxType=${paxType}, total=${totalTarifa}, fee=${feeTucano}, neto=${totalTarifa+feeTucano}`);
            return {
              neto: totalTarifa + feeTucano,
              tipo_tarifa: f.fareType || 'PNEG',
              comision_over: ((f.commissionRule?.obtained?.valueApplied || f.commissionRule?.obtained?.amount || 0) + (f.overCommissionRule?.valueApplied || f.overCommissionRule?.amount || 0)),
              passengerDiscountType: paxType
            };
          });
          // Limit fareInfo to actual passenger count - take the LAST entries (most recent pricing)
          const totalPaxCount = (reserva.adultos || 0) + (reserva.ninos || 0) + (reserva.infantes || 0);
          if (fareInfo.length > totalPaxCount && totalPaxCount > 0) {
            console.log(`[PDF] Trimming fareInfo from ${fareInfo.length} to last ${totalPaxCount} (most recent pricing)`);
            fareInfo = fareInfo.slice(-totalPaxCount);
          }
        }
      } catch(e) {
        console.log('[PDF] Error API, usando datos locales:', e.message);
      }
    }

    // Fallback vuelos desde itinerario local
    if (!vuelos.length && (reserva.itinerario_json || reserva.itinerario)) {
      try {
        const raw = reserva.itinerario_json || reserva.itinerario;
        const itin = typeof raw === 'string' ? JSON.parse(raw) : raw;
        const arr = itin.segments || (Array.isArray(itin) ? itin : []);
        
        // GEA itinerarios have nested segmentos per leg
        const expanded = [];
        for (const leg of arr) {
          if (leg.segmentos && leg.segmentos.length) {
            // GEA: expand segments from each leg
            for (const seg of leg.segmentos) {
              expanded.push({
                departureAirportCode: seg.origen || '',
                arrivalAirportCode: seg.destino || '',
                departureDate: seg.salida || '',
                arrivalDate: seg.llegada || '',
                flightNumber: seg.vuelo || '',
                marketingAirlineCode: seg.aerolinea || (seg.vuelo || '').substring(0, 2),
                _depCity: seg.origenCiudad || '',
                _arrCity: seg.destinoCiudad || ''
              });
            }
          } else {
            // Tucano / simple format
            expanded.push({
              departureAirportCode: leg.departureAirportCode || leg.origen || leg.origin || '',
              arrivalAirportCode: leg.arrivalAirportCode || leg.destino || leg.destination || '',
              departureDate: leg.departureDate || leg.salida || leg.departureDateTime || '',
              arrivalDate: leg.arrivalDate || leg.llegada || leg.arrivalDateTime || '',
              flightNumber: leg.flightNumber || leg.vuelo || leg.numero_vuelo || '',
              marketingAirlineCode: leg.marketingAirlineCode || (leg.vuelo || '').substring(0, 2),
              _depCity: leg.origenCiudad || '',
              _arrCity: leg.destinoCiudad || ''
            });
          }
        }
        vuelos = expanded;
        
        // Build airportsInfo from city names in itinerario + global map
        for (const v of vuelos) {
          if (v.departureAirportCode && !airportsInfo[v.departureAirportCode]) {
            const city = v._depCity || AIRPORT_CITY_MAP[v.departureAirportCode] || '';
            if (city) airportsInfo[v.departureAirportCode] = { cityName: city };
          }
          if (v.arrivalAirportCode && !airportsInfo[v.arrivalAirportCode]) {
            const city = v._arrCity || AIRPORT_CITY_MAP[v.arrivalAirportCode] || '';
            if (city) airportsInfo[v.arrivalAirportCode] = { cityName: city };
          }
        }
      } catch(e) { console.log('[PDF] Error parsing itinerario:', e.message); }
    }

    // Pasajeros - fallback a pasajeros_json si no hay reserva_pasajeros
    let pasajeros = (reserva.pasajeros_info || []).filter(p => p.nombre).map(p => ({
      nombre: p.nombre,
      tipo: p.tipo || 'ADT',
      documento: p.doc_tipo && p.doc_numero ? `${p.doc_tipo} ${p.doc_numero}` : ''
    }));
    if (!pasajeros.length && reserva.pasajeros_json) {
      try {
        const pj = typeof reserva.pasajeros_json === 'string' ? JSON.parse(reserva.pasajeros_json) : reserva.pasajeros_json;
        if (Array.isArray(pj)) {
          pasajeros = pj.map(p => ({
            nombre: `${p.apellido || ''}, ${p.nombre || ''}`.trim(),
            tipo: p.tipo || 'ADT',
            documento: p.docTipo && p.docNumero ? `${p.docTipo} ${p.docNumero}` : (p.docNumero || '')
          }));
        }
      } catch(e) {}
    }

    // Calcular precios de venta
    const { vendedor: reqVendedor } = req.body || {};
    let preciosVenta = [];
    const tipoLabels = { ADT: 'adulto', CHD: 'menor', CNN: 'menor', INF: 'infante' };

    // Usar storedFaresInformation de la API para desglose por tipo de pasajero
    if (fareInfo && fareInfo.length) {
      // Si hay neto guardado en DB (con comisiones descontadas), ajustar proporcionalmente
      const fareTotal = fareInfo.reduce((s, f) => s + f.neto, 0);
      const dbTotal = reserva.precio_usd || 0;
      const scale = (dbTotal > 0 && fareTotal > 0) ? dbTotal / fareTotal : 1;
      if (scale !== 1) console.log(`[PDF] Ajustando netos: fareTotal=${fareTotal}, dbTotal=${dbTotal}, scale=${scale.toFixed(4)}`);
      
      // Agrupar por tipo de pasajero
      const grouped = {};
      for (const f of fareInfo) {
        const tipo = tipoLabels[f.passengerDiscountType] || 'adulto';
        const netoAjustado = f.neto * scale;
        if (!grouped[tipo]) {
          grouped[tipo] = { tipo, cantidad: 0, neto: netoAjustado, tipo_tarifa: f.tipo_tarifa, comision_over: f.comision_over };
        }
        grouped[tipo].cantidad++;
      }
      preciosVenta = Object.values(grouped);
      
      // Fix: si hay menos fareInfo entries que pasajeros, el neto podría ser el total
      // de todos los pax de ese tipo, no por persona. Verificar y corregir.
      const totalPaxActual = pasajeros.length || 1;
      const sumNeto = preciosVenta.reduce((s, p) => s + (p.neto * p.cantidad), 0);
      const dbNeto = reserva.precio_usd || 0;
      // Si sumNeto ≈ dbNeto × (N pasajeros / N fareEntries), las fares son TOTAL no per-pax
      if (fareInfo.length < totalPaxActual && fareInfo.length > 0 && dbNeto > 0) {
        // Each fareInfo entry covers multiple passengers - divide neto by actual count
        for (const pp of preciosVenta) {
          // Count actual pax of this type from passenger list
          const tipoMap = { 'adulto': ['ADT','AD'], 'menor': ['CHD','CNN','CH'], 'bebé': ['INF','INS'], 'infante': ['INF','INS'] };
          const tipoCodes = tipoMap[pp.tipo] || ['ADT'];
          const realCount = pasajeros.filter(p => tipoCodes.includes((p.tipo || 'ADT').toUpperCase())).length || pp.cantidad;
          if (realCount > 1 && pp.cantidad <= 1) {
            console.log(`[PDF] Fix: dividiendo neto ${pp.neto} por ${realCount} pax reales (tipo ${pp.tipo})`);
            pp.neto = pp.neto / realCount;
            pp.cantidad = realCount;
          }
        }
      }
      
      console.log('[PDF] Usando fareInfo API (ajustado):', JSON.stringify(preciosVenta));
    } else if (reserva.precio_usd) {
      // Fallback: usar DB neto total (sin desglose por tipo)
      preciosVenta = [{
        tipo: 'adulto', cantidad: pasajeros.length || 1,
        neto: reserva.precio_usd / (pasajeros.length || 1),
        tipo_tarifa: 'PNEG', comision_over: 0
      }];
      console.log('[PDF] Usando neto DB:', reserva.precio_usd);
    }

    // ── GENERAR PDF CON PDFKIT ──
    const vendedor = reqVendedor || 'guido';
    const contacto = CONTACTOS[vendedor] || CONTACTOS.guido;
    const NAVY = '#1B3A5C';

    // Helper: Title Case
    function titleCase(str) {
      if (!str) return '';
      return str.toLowerCase().replace(/\b\w/g, c => c.toUpperCase());
    }

    const logoCandidates = [
      pathModule.join(__dirname, 'public', 'logo_transparent.png'),
      pathModule.join(__dirname, 'logo_transparent.png'),
    ];
    const logoFinal = logoCandidates.find(p => fsModule.existsSync(p)) || null;

    const doc = new PDFDocument({ size: 'A4', margin: 40, bufferPages: true });
    const chunks = [];
    doc.on('data', c => chunks.push(c));

    const BOLD = HAS_UNICODE_FONT ? 'UCBold' : 'Helvetica-Bold';
    const REGULAR = HAS_UNICODE_FONT ? 'UCRegular' : 'Helvetica';
    if (HAS_UNICODE_FONT) {
      doc.registerFont('UCRegular', FONT_REGULAR);
      doc.registerFont('UCBold', FONT_BOLD);
    }

    const pdfPromise = new Promise((resolve, reject) => {
      doc.on('end', () => resolve(Buffer.concat(chunks)));
      doc.on('error', reject);
    });

    const pageW = doc.page.width - 80;
    const LEFT = 40;

    // Fecha
    doc.font(REGULAR).fontSize(9).fillColor('#666666');
    doc.text(new Date().toLocaleDateString('es-AR'), LEFT, 40, { width: pageW, align: 'right' });

    // Logo
    let y = 55;
    if (logoFinal) {
      doc.image(logoFinal, (doc.page.width - 160) / 2, y, { width: 160 });
      y += 130;
    }

    // Título en una sola línea
    const pdfTitulo = reserva.estado === 'EMITIDA' ? 'Confirmación de Vuelo' : 'Confirmación de Reserva';
    const titleText = `${pdfTitulo}  —  ${reserva.pnr}`;
    doc.font(BOLD).fontSize(14).fillColor(NAVY);
    doc.text(titleText, LEFT, y, { width: pageW, align: 'center' });
    y = doc.y + 8;

    // Línea
    doc.moveTo(LEFT, y).lineTo(doc.page.width - LEFT, y).strokeColor(NAVY).lineWidth(2).stroke();
    y += 15;

    // ── PASAJEROS ──
    doc.font(BOLD).fontSize(9).fillColor(NAVY).text('PASAJEROS', LEFT, y);
    y = doc.y + 6;
    for (const p of pasajeros) {
      const tipoLabel = tipoLabels[p.tipo] || p.tipo || 'Adulto';
      const capTipo = tipoLabel.charAt(0).toUpperCase() + tipoLabel.slice(1);
      const docStr = p.documento ? `  —  ${p.documento}` : '';
      doc.font(BOLD).fontSize(9).fillColor('#000000').text(`${p.nombre} `, LEFT, y, { continued: true });
      doc.font(REGULAR).fontSize(9).fillColor('#555555').text(`(${capTipo})${docStr}`);
      y = doc.y + 3;
    }
    y += 8;

    // ── ITINERARIO ──
    // Resolve airline code to full name if needed
    const commonAirlines = {
      'AR':'Aerolíneas Argentinas','LA':'Latam Airlines','AF':'Air France','DL':'Delta Airlines',
      'AA':'American Airlines','UA':'United Airlines','IB':'Iberia','BA':'British Airways',
      'LH':'Lufthansa','AZ':'ITA Airways','KL':'KLM','UX':'Air Europa','ET':'Ethiopian Airlines',
      'TK':'Turkish Airlines','EK':'Emirates','QR':'Qatar Airways','AC':'Air Canada',
      'AV':'Avianca','CM':'Copa Airlines','G3':'Gol','JJ':'Latam Brasil','AM':'Aeromexico',
      'TP':'TAP Portugal','LY':'El Al','QF':'Qantas','SQ':'Singapore Airlines','CX':'Cathay Pacific'
    };
    if (aerolinea && aerolinea.length <= 2) aerolinea = commonAirlines[aerolinea.toUpperCase()] || aerolinea;
    const airlineTitleCase = titleCase(aerolinea);
    const tituloItin = airlineTitleCase ? `ITINERARIO  —  ${airlineTitleCase}` : 'ITINERARIO';
    doc.font(BOLD).fontSize(9).fillColor(NAVY).text(tituloItin, LEFT, y);
    y = doc.y + 6;

    for (const v of vuelos) {
      const dep = v.departureAirportCode || '';
      const arr = v.arrivalAirportCode || '';
      const depDate = v.departureDate || '';
      const arrDate = v.arrivalDate || '';
      const flight = v.flightNumber || `${v.marketingAirlineCode || ''} ${v.flightNumber || ''}`.trim();

      let fecha = '';
      let salida = '', llegada = '';
      try {
        const dt = new Date(depDate);
        const meses = ['ene','feb','mar','abr','may','jun','jul','ago','sep','oct','nov','dic'];
        fecha = `${String(dt.getDate()).padStart(2,'0')}/${meses[dt.getMonth()]}`;
        salida = `${String(dt.getHours()).padStart(2,'0')}.${String(dt.getMinutes()).padStart(2,'0')}`;
        const at = new Date(arrDate);
        llegada = `${String(at.getHours()).padStart(2,'0')}.${String(at.getMinutes()).padStart(2,'0')}`;
      } catch(e) {}

      const depCityRaw = airportsInfo[dep]?.cityName || AIRPORT_CITY_MAP[dep] || '';
      const arrCityRaw = airportsInfo[arr]?.cityName || AIRPORT_CITY_MAP[arr] || '';
      const depCity = depCityRaw ? `${titleCase(depCityRaw)} (${dep})` : dep;
      const arrCity = arrCityRaw ? `${titleCase(arrCityRaw)} (${arr})` : arr;

      doc.font(BOLD).fontSize(10).fillColor('#000000');
      doc.text(`${fecha}   ${depCity}  →  ${arrCity}     ${salida} → ${llegada}`, LEFT, y);
      y = doc.y + 1;
      if (flight) {
        doc.font(REGULAR).fontSize(8).fillColor('#555555').text(flight, LEFT, y);
        y = doc.y + 6;
      }
    }
    y += 8;

    // ── PRECIO DE VENTA (solo si NO está emitida) ──
    const esEmitida = reserva.estado === 'EMITIDA';
    
    if (!esEmitida && preciosVenta.length) {
      // Use actual passenger count, not fare entry count
      const realPaxCount = pasajeros.length || preciosVenta.reduce((s, p) => s + p.cantidad, 0);
      const totalPax = realPaxCount;
      const multiTipos = preciosVenta.length > 1;
      doc.font(BOLD).fontSize(9).fillColor(NAVY).text(totalPax === 1 ? 'PRECIO' : 'PRECIOS', LEFT, y);
      y = doc.y + 6;
      for (const pp of preciosVenta) {
        // Adjust cantidad to match real passengers of this type
        const realCantidad = multiTipos ? pp.cantidad : totalPax;
        const precioVenta = calcularPrecio(pp.neto, pp.tipo_tarifa, pp.comision_over);
        const linea = etiquetaPrecio(precioVenta, pp.tipo, realCantidad, totalPax, multiTipos);
        doc.font(BOLD).fontSize(11).fillColor(NAVY).text(linea, LEFT, y);
        y = doc.y + 4;
      }
    }

    // ── TICKETS (solo si emitida) ──
    if (esEmitida) {
      let tickets = [];
      try {
        const ed = typeof reserva.emision_data === 'string' ? JSON.parse(reserva.emision_data) : reserva.emision_data;
        if (ed && ed.tickets) tickets = ed.tickets;
      } catch(e) {}
      if (tickets.length) {
        doc.font(BOLD).fontSize(9).fillColor(NAVY).text('TICKETS', LEFT, y);
        y = doc.y + 6;
        for (const t of tickets) {
          const ticketNum = (t.carrier || '') + '-' + (t.numero || t.number || '');
          doc.font(REGULAR).fontSize(9).fillColor('#000000').text(`  • ${ticketNum}`, LEFT, y);
          y = doc.y + 3;
        }
        y += 4;
      }
    }

    // ── CONDICIONES (siempre, emitida o no) ──
    {
      // Fallback: read from DB if API didn't provide penalties
      let pen = penalidades;
      if (!pen && reserva.penalidades_json) {
        try {
          pen = typeof reserva.penalidades_json === 'string' ? JSON.parse(reserva.penalidades_json) : reserva.penalidades_json;
          console.log('[PDF] Using penalties from DB');
        } catch(e) {}
      }
      if (pen && (pen.cambio_antes || pen.cambio_durante || pen.devolucion_antes || pen.devolucion_durante || pen.cambio || pen.cancelacion)) {
        y += 6;
        doc.font(BOLD).fontSize(8).fillColor(NAVY).text('Condiciones:', LEFT, y);
        y = doc.y + 3;
        doc.font(REGULAR).fontSize(7.5).fillColor('#555555');
        const condiciones = [
          { label: 'Cambio (antes del viaje)', data: pen.cambio_antes || pen.cambio, isDevolucion: false },
          { label: 'Cambio (durante el viaje)', data: pen.cambio_durante, isDevolucion: false },
          { label: 'Devolución (antes del viaje)', data: pen.devolucion_antes || pen.cancelacion, isDevolucion: true },
          { label: 'Devolución (durante el viaje)', data: pen.devolucion_durante, isDevolucion: true }
        ];
        for (const cond of condiciones) {
          if (cond.data) {
            const estado = cond.data.permite !== false ? 'Permite' : 'No permite';
            const montoVal = cond.isDevolucion && cond.data.permite !== false ? ((cond.data.monto || 0) + 100) : (cond.data.monto || 0);
            const montoStr = cond.data.permite !== false ? ` — ${cond.data.moneda} ${montoVal}` : '';
            doc.text(`  • ${cond.label}: ${estado}${montoStr}`, LEFT, y);
            y = doc.y + 2;
          }
        }
        doc.moveDown(0.2);
        doc.font(REGULAR).fontSize(6.5).fillColor('#888888').text('Los cambios siempre están sujetos a diferencia de tarifa', LEFT, y);
        y = doc.y + 2;
      }
    }

    // ── FOOTER (posición absoluta en cada página) ──
    const pages = doc.bufferedPageRange();
    for (let i = 0; i < pages.count; i++) {
      doc.switchToPage(i);
      const footerY = doc.page.height - 70;
      doc.moveTo(LEFT, footerY).lineTo(doc.page.width - LEFT, footerY).strokeColor(NAVY).lineWidth(1.5).stroke();
      doc.font(BOLD).fontSize(9).fillColor(NAVY);
      doc.text('Contacto:', LEFT, footerY + 8, { lineBreak: false });
      doc.text(contacto.nombre, LEFT + 55, footerY + 8, { lineBreak: false });
      doc.font(REGULAR).fontSize(9).fillColor('#333333');
      doc.text(contacto.mail, LEFT, footerY + 20, { lineBreak: false });
      doc.text(contacto.tel, LEFT, footerY + 32, { lineBreak: false });
    }

    doc.end();
    const pdfBuffer = await pdfPromise;

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `inline; filename="Reserva_${reserva.pnr}.pdf"`);
    res.send(pdfBuffer);
  } catch(e) {
    console.error('[PDF Reserva] Error:', e.message);
    res.status(500).json({ ok: false, error: e.message });
  }
});

app.listen(PORT, () => console.log(`✅ Puerto ${PORT}`));

// ─── DETALLE DE VUELO (desglose de precio) ───
app.get('/detalle-vuelo', async (req, res) => {
  const { searchId, quotationId } = req.query;
  
  // ─── SABRE DIRECT: return cached price data ───
  if (String(quotationId).startsWith('sabre_')) {
    const cached = sabreSolutionsCache.get(quotationId);
    if (!cached) return res.json({ ok: false, error: 'Solución Sabre expirada. Buscá de nuevo.' });
    
    const desglose = [];
    for (const fare of (cached.fareList || [])) {
      const tipo = (fare.passenger_type || 'ADT').toUpperCase();
      desglose.push({
        tipo: tipo === 'CNN' ? 'CHD' : tipo,
        cantidad: fare.quantity || 1,
        tarifa: fare.base || 0,
        impuestos: fare.total_taxes || 0,
        fee: 0, descuento: 0,
        total: fare.total || 0,
        detImpuestos: []
      });
    }
    
    // Try to get baggage and penalty info
    let penalidades = { cambio_antes: null, cambio_durante: null, devolucion_antes: null, devolucion_durante: null };
    try {
      const pInfo = cached.pricingInfo || {};
      // Check penalties from fare info
      const fareInfos = pInfo.FareInfos?.FareInfo || [];
      for (const fi of fareInfos) {
        if (fi.TPA_Extensions?.Penalties) {
          const pen = fi.TPA_Extensions.Penalties;
          if (pen.Change) penalidades.cambio_antes = pen.Change.Amount ? `USD ${pen.Change.Amount}` : (pen.Change.Applicability || null);
          if (pen.Refund) penalidades.devolucion_antes = pen.Refund.Amount ? `USD ${pen.Refund.Amount}` : (pen.Refund.Applicability || null);
        }
      }
    } catch(e) {}
    
    return res.json({
      ok: true, source: 'sabre',
      desglose,
      penalidades,
      precioNeto: cached.totalUSD,
      moneda: cached.currency || 'USD',
      reglas: []
    });
  }
  
  // ─── GEA / Lleego: return cached price data + fetch conditions ───
  if (String(quotationId).startsWith('lleego_')) {
    const cached = lleegoSolutionsCache.get(quotationId);
    if (!cached) return res.json({ ok: false, error: 'Solución GEA expirada. Buscá de nuevo.' });
    
    const sol = cached.sol;
    const price = sol.total_price || {};
    
    // Extract per-pax pricing from fare_list (available in search data)
    const desglose = [];
    const fareList = sol.data?.fare_list || [];
    
    if (fareList.length) {
      for (const fare of fareList) {
        const tipo = (fare.passenger_type_normalized || fare.passenger_type || 'ADT').toUpperCase();
        const qty = fare.quantity || 1;
        // fare_list values are PER PASSENGER (total_price = sum of per_pax * qty)
        desglose.push({
          tipo,
          cantidad: qty,
          tarifa: fare.base || 0,
          impuestos: fare.total_taxes || 0,
          fee: 0, descuento: 0,
          total: fare.total || fare.amount || ((fare.base||0) + (fare.total_taxes||0)),
          detImpuestos: []
        });
      }
    } else {
      // Fallback: single total
      const { adultos = 1, ninos = 0, infantes = 0 } = cached.paxCounts || {};
      desglose.push({
        tipo: 'ADT', cantidad: adultos + ninos + infantes,
        tarifa: price.base || 0,
        impuestos: price.total_taxes || ((price.total||0) - (price.base||0)),
        fee: 0, descuento: 0,
        total: price.total || 0,
        detImpuestos: []
      });
    }
    
    // Fetch conditions from Lleego policy endpoint
    let reglas = [];
    let penalidades = { cambio_antes: null, cambio_durante: null, devolucion_antes: null, devolucion_durante: null, cambio: null, cancelacion: null };
    try {
      const llToken = await getLleegoToken();
      if (llToken && cached.searchToken) {
        // Build journey codes for pricing endpoint (policy doesn't work for NDC)
        const _assocs2 = sol.data?.associations || [];
        const _jCodes = [];
        for (const _a of _assocs2) {
          const _jR = (_a.journey_references || [])[0]; if (!_jR) continue;
          const _j = cached.journeys[_jR]; if (!_j) continue;
          const _fS = (_j.segments || [])[0];
          const _s = cached.segments[_fS]; if (!_s) continue;
          const _dd = _s.departure_date ? _s.departure_date.substring(0,10).replace(/-/g,'') : '';
          const _lS = (_j.segments || []).slice(-1)[0];
          const _ls = cached.segments[_lS] || _s;
          _jCodes.push(`${_s.marketing_company}${_s.transport_number}${_dd}${_s.departure||''}${_ls.arrival||''}`);
        }
        const _jp = _jCodes.map((j,i) => `&journey0${i}=${j}`).join('');
        const policyUrl = `https://api-tr.lleego.com/api/v2/transport/pricing?format=json&solutionID0=${sol.id}${_jp}&extend=true&locale=es-ar`;
        console.log('[Lleego] Policy URL:', policyUrl);
        const policyRes = await fetch(policyUrl, {
          headers: {
            'Authorization': `Bearer ${llToken}`,
            'x-api-key': LLEEGO_API_KEY,
            'lang': 'es-ar'
          }
        });
        if (policyRes.ok) {
          const policyData = await policyRes.json();
          console.log('[Lleego] Pricing response:', JSON.stringify(policyData).substring(0, 1200));
          // Parse penalties from pricing notes (NDC returns Refund/Change categories)
          const _notes = policyData.notes || policyData.data?.notes || [];
          for (const n of _notes) {
            const cat = (n.category || '').toLowerCase();
            const desc = (n.description || n.message || '').trim();
            const sn = (n.short_name || '');
            if (cat === 'refund' || cat.includes('refund')) {
              const notAllowed = desc.toLowerCase().includes('not allowed');
              if (sn.includes('Prior') || sn.includes('Before')) penalidades.devolucion_antes = { permite: !notAllowed, monto: 0, moneda: 'USD', detalle: desc };
              else if (sn.includes('After')) penalidades.devolucion_durante = { permite: !notAllowed, monto: 0, moneda: 'USD', detalle: desc };
              if (!penalidades.cancelacion) penalidades.cancelacion = { permite: !notAllowed, monto: 0, moneda: 'USD' };
              reglas.push({ type: 'F', text: `${sn}: ${desc}` });
            }
            if (cat === 'change' || cat === 'changes') {
              const am = desc.match(/(\d+)\s*USD/i);
              const monto = am ? parseInt(am[1]) : 0;
              const notAllowed = desc.toLowerCase().includes('not allowed');
              if (sn.includes('Prior') || sn.includes('Before')) penalidades.cambio_antes = { permite: !notAllowed, monto, moneda: 'USD', detalle: desc };
              else if (sn.includes('After')) penalidades.cambio_durante = { permite: !notAllowed, monto, moneda: 'USD', detalle: desc };
              if (!penalidades.cambio) penalidades.cambio = { permite: !notAllowed, monto, moneda: 'USD' };
              reglas.push({ type: 'C', text: `${sn}: ${desc}` });
            }
          }
          // Also check price_class_supplements
          const _supps = policyData.price_class_supplements || policyData.data?.price_class_supplements || [];
          for (const sp of _supps) {
            const cat = (sp.category || '').toLowerCase();
            const desc = (sp.description || '').trim();
            if (cat === 'refund' && !penalidades.devolucion_antes) {
              const na = (sp.indicator === 'NOF');
              penalidades.devolucion_antes = { permite: !na, monto: 0, moneda: 'USD', detalle: desc };
              penalidades.devolucion_durante = { permite: !na, monto: 0, moneda: 'USD', detalle: desc };
            }
            if ((cat === 'changes' || cat === 'change') && !penalidades.cambio_antes) {
              const na = (sp.indicator === 'NOF');
              const am = desc.match(/(\d+)\s*USD/i);
              penalidades.cambio_antes = { permite: !na, monto: am ? parseInt(am[1]) : 0, moneda: 'USD', detalle: desc };
            }
          }
          console.log('[Lleego] Parsed penalties:', JSON.stringify(penalidades));
        }
      }
    } catch(e) {
      console.log('[Lleego] Pricing/penalties error (non-fatal):', e.message);
    }
    
    // Cache GEA penalties
    if (penalidades && quotationId) penaltiesCache.set(quotationId, penalidades);

    return res.json({
      ok: true,
      tarifa: price.base || price.fare || 0,
      impuestos: price.taxes || price.tax || 0,
      fee: 0,
      total: price.total || 0,
      moneda: price.currency || 'USD',
      desglose,
      penalidades,
      reglas,
      fuente: 'GEA'
    });
  }
  
  // ─── GLAS / Tucano ───
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

    // Penalidades - extraer las 4 combinaciones (cambio/devolución × antes/durante)
    const extractPenalty = (type, applicability) => {
      const p = penalties.find(pen => pen.type === type && pen.applicability === applicability);
      if (!p) return null;
      return { monto: p.amount || 0, moneda: p.currency || 'USD', permite: !!p.enabled };
    };

    const penalidades = {
      cambio_antes: extractPenalty(0, 0),
      cambio_durante: extractPenalty(0, 1),
      devolucion_antes: extractPenalty(1, 0),
      devolucion_durante: extractPenalty(1, 1),
      // Mantener compatibilidad con formato viejo
      cambio: extractPenalty(0, 0),
      cancelacion: extractPenalty(1, 0)
    };
    console.log('[Detalle] Penalties raw:', JSON.stringify(penalties).substring(0, 500));
    console.log('[Detalle] Penalidades parsed:', JSON.stringify(penalidades));

    // Cache penalties for use when creating reservation
    if (penalidades && quotationId) {
      penaltiesCache.set(quotationId, penalidades);
    }

    res.json({
      ok: true,
      tarifa: amounts.fareAmount || 0,
      impuestos: amounts.taxAmount || 0,
      fee: amounts.feeAmount || 0,
      total: amounts.sellingPriceAmount || 0,
      moneda: amounts.fareCurrency || 'USD',
      desglose,
      penalidades,
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

      // ── EQUIPAJE ──
      if (op.equipaje) {
        doc.moveDown(0.3);
        doc.fontSize(8).font(BOLD).fillColor(NAVY).text('Equipaje:', PAGE_LEFT);
        doc.moveDown(0.2);
        const eq = op.equipaje;
        const eqItems = [
          { label: 'Mochila', valor: eq.handOn.label, ok: eq.handOn.incluido },
          { label: 'Carry on', valor: eq.carryOn.label, ok: eq.carryOn.incluido },
          { label: 'Despachado', valor: eq.checked.label, ok: eq.checked.incluido }
        ];
        for (const item of eqItems) {
          doc.font(REGULAR).fontSize(7.5).fillColor(item.ok ? '#2d8a4e' : '#999999');
          doc.text(`  • ${item.label}: ${item.valor}`, PAGE_LEFT);
        }
      }

      // ── PENALIDADES / CONDICIONES ──
      console.log(`[PDF-Cotizacion] Penalidades para opción: ${JSON.stringify(op.penalidades)}`);
      const pen = op.penalidades;
      if (pen && (pen.cambio_antes || pen.cambio_durante || pen.devolucion_antes || pen.devolucion_durante || pen.cambio || pen.cancelacion)) {
        doc.moveDown(0.5);
        doc.fontSize(8).font(BOLD).fillColor(NAVY).text('Condiciones:', PAGE_LEFT);
        doc.moveDown(0.2);
        doc.font(REGULAR).fontSize(7.5).fillColor('#555555');
        const condiciones = [
          { label: 'Cambio (antes del viaje)', data: pen.cambio_antes || pen.cambio, isDevolucion: false },
          { label: 'Cambio (durante el viaje)', data: pen.cambio_durante, isDevolucion: false },
          { label: 'Devolución (antes del viaje)', data: pen.devolucion_antes || pen.cancelacion, isDevolucion: true },
          { label: 'Devolución (durante el viaje)', data: pen.devolucion_durante, isDevolucion: true }
        ];
        for (const cond of condiciones) {
          if (cond.data) {
            const estado = cond.data.permite !== false ? 'Permite' : 'No permite';
            const montoVal = cond.isDevolucion && cond.data.permite !== false ? ((cond.data.monto || 0) + 100) : (cond.data.monto || 0);
            const montoStr = cond.data.permite !== false ? ` — ${cond.data.moneda} ${montoVal}` : '';
            doc.text(`  • ${cond.label}: ${estado}${montoStr}`, PAGE_LEFT);
          } else {
            doc.text(`  • ${cond.label}: No disponible`, PAGE_LEFT);
          }
        }
        doc.moveDown(0.2);
        doc.font(REGULAR).fontSize(6.5).fillColor('#888888').text('Los cambios siempre están sujetos a diferencia de tarifa', PAGE_LEFT);
        console.log(`[PDF-Cotizacion] Renderizado: Condiciones completas`);
      }
    }

    // Dibujar footer en TODAS las páginas
    const pages = doc.bufferedPageRange();
    for (let i = 0; i < pages.count; i++) {
      doc.switchToPage(i);
      dibujarFooterEnPagina();
    }
    doc.flushPages();
    doc.end();
  });
}

app.post('/generar-cotizacion', async (req, res) => {
  const { opciones, vendedor, nombreCliente } = req.body;
  try {
    const token = await getToken();

    const opcionesCompletas = await Promise.all(opciones.map(async (op) => {
      // ─── SABRE: use cached data ───
      if (String(op.quotationId).startsWith('sabre_')) {
        const cached = sabreSolutionsCache.get(op.quotationId);
        if (!cached) throw new Error('Solución Sabre expirada. Buscá de nuevo.');
        
        const pasajeros = [];
        for (const fare of (cached.fareList || [])) {
          const t = (fare.passenger_type || 'ADT').toUpperCase();
          pasajeros.push({
            tipo: t === 'ADT' ? 'adulto' : t === 'CNN' || t === 'CHD' ? 'menor' : 'bebé',
            cantidad: fare.quantity || 1, neto: fare.total || 0,
            tipo_tarifa: 'PUB', comision_over: 0
          });
        }
        
        const vuelos = [];
        for (const leg of cached.legs) {
          for (const seg of leg.segmentos) {
            const depDate = seg.salida ? new Date(seg.salida) : null;
            const arrDate = seg.llegada ? new Date(seg.llegada) : null;
            vuelos.push({
              fecha: depDate ? `${String(depDate.getDate()).padStart(2,'0')}/${String(depDate.getMonth()+1).padStart(2,'0')}` : '',
              origen: `${AIRPORT_CITY_MAP[seg.origen] || seg.origen} (${seg.origen})`,
              destino: `${AIRPORT_CITY_MAP[seg.destino] || seg.destino} (${seg.destino})`,
              salida: depDate ? `${String(depDate.getHours()).padStart(2,'0')}.${String(depDate.getMinutes()).padStart(2,'0')}` : '',
              llegada: arrDate ? `${String(arrDate.getHours()).padStart(2,'0')}.${String(arrDate.getMinutes()).padStart(2,'0')}` : '',
              numero_vuelo: seg.vuelo,
              brand: ''
            });
          }
        }
        
        // Get penalties from cache
        const cachedPenCotSabre = penaltiesCache.get(op.quotationId) || null;

        return {
          aerolinea: cached.validatingCarrier || '',
          vuelos, detalle_vuelo: 'Economica', pasajeros, penalidades: cachedPenCotSabre,
          equipaje: {
            handOn: { label: 'Incluida', incluido: true },
            carryOn: { label: 'No informado', incluido: false },
            checked: { label: 'No informado', incluido: false }
          }
        };
      }
      // ─── GEA: use cached data ───
      if (String(op.quotationId).startsWith('lleego_')) {
        const cached = lleegoSolutionsCache.get(op.quotationId);
        if (!cached) throw new Error('Solución GEA expirada. Buscá de nuevo.');
        const sol = cached.sol;
        const price = sol.total_price || {};
        
        // Build pasajeros from fare_list (per-pax breakdown)
        const pasajeros = [];
        const fareList = sol.data?.fare_list || [];
        if (fareList.length) {
          for (const fare of fareList) {
            const t = (fare.passenger_type_normalized || fare.passenger_type || 'ADT').toUpperCase();
            const qty = fare.quantity || 1;
            // fare_list values are per passenger
            pasajeros.push({
              tipo: t === 'ADT' ? 'adulto' : t === 'CHD' || t === 'CNN' ? 'menor' : 'bebé',
              cantidad: qty, neto: fare.total || fare.amount || 0,
              tipo_tarifa: 'PUB', comision_over: 0
            });
          }
        } else {
          pasajeros.push({ tipo: 'adulto', cantidad: 1, neto: price.total || 0, tipo_tarifa: 'PUB', comision_over: 0 });
        }
        
        // AIRPORT_CITY fallback map (same as Tucano uses)
        const AIRPORT_CITY = {
          'EZE':'Buenos Aires','AEP':'Buenos Aires','MIA':'Miami','MAD':'Madrid','BCN':'Barcelona',
          'FCO':'Roma','CDG':'Paris','ORY':'Paris','LHR':'Londres','LGW':'Londres','FRA':'Frankfurt',
          'AMS':'Amsterdam','IST':'Estambul','DXB':'Dubai','DOH':'Doha','TLV':'Tel Aviv',
          'ADD':'Addis Abeba','GRU':'San Pablo','SCL':'Santiago','LIM':'Lima','BOG':'Bogota',
          'PTY':'Panama','CUN':'Cancun','MEX':'Mexico DF','JFK':'Nueva York','LAX':'Los Angeles',
          'MVD':'Montevideo','COR':'Cordoba','MDZ':'Mendoza','BRC':'Bariloche','IGR':'Iguazu',
          'FTE':'El Calafate','USH':'Ushuaia','SLA':'Salta','TUC':'Tucuman',
          'MXP':'Milan','MUC':'Munich','ZRH':'Zurich','VIE':'Viena','LIS':'Lisboa',
          'NRT':'Tokio','ICN':'Seul','SIN':'Singapur','BKK':'Bangkok','SYD':'Sydney',
          'JNB':'Johannesburgo','CAI':'El Cairo','NBO':'Nairobi','ATL':'Atlanta',
          'ORD':'Chicago','DFW':'Dallas','FLN':'Florianopolis','POA':'Porto Alegre'
        };
        
        // Build vuelos in cotizacion format: { fecha, origen, destino, salida, llegada, numero_vuelo, brand }
        const vuelos = [];
        const assocs = sol.data?.associations || [];
        for (const assoc of assocs) {
          const journeyRefs = assoc.journey_references || [];
          for (const jRef of journeyRefs) {
            const journey = cached.journeys[jRef]; if (!journey) continue;
            const jSegs = journey.segments || [];
            for (const sid of jSegs) {
              const seg = cached.segments[sid]; if (!seg) continue;
              const depPort = cached.ports[seg.departure] || {};
              const arrPort = cached.ports[seg.arrival] || {};
              const depCity = AIRPORT_CITY[seg.departure] || depPort.city_name || '';
              const arrCity = AIRPORT_CITY[seg.arrival] || arrPort.city_name || '';
              const dep = new Date(seg.departure_date);
              const arr = new Date(seg.arrival_date);
              
              const origenStr = depCity ? `${depCity} (${seg.departure})` : `(${seg.departure})`;
              const destinoStr = arrCity ? `${arrCity} (${seg.arrival})` : `(${seg.arrival})`;
              
              vuelos.push({
                fecha: `${String(dep.getDate()).padStart(2,'0')}/${String(dep.getMonth()+1).padStart(2,'0')}`,
                origen: origenStr,
                destino: destinoStr,
                salida: `${String(dep.getHours()).padStart(2,'0')}.${String(dep.getMinutes()).padStart(2,'0')}`,
                llegada: `${String(arr.getHours()).padStart(2,'0')}.${String(arr.getMinutes()).padStart(2,'0')}`,
                numero_vuelo: `${seg.marketing_company} ${seg.transport_number}`,
                brand: ''
              });
            }
          }
        }
        
        const validating = assocs[0]?.validating_company || '';
        const airlineName = cached.companies[validating]?.name || validating;
        
        return { 
          aerolinea: airlineName, vuelos, 
          detalle_vuelo: 'Economica', 
          pasajeros, penalidades: penaltiesCache.get(op.quotationId) || null, 
          equipaje: op.equipaje || null 
        };
      }
      
      // ─── Tucano: use GLAS API ───
      const r = await fetch(`${API_BASE}/FlightSearch/ItineraryDetailRemake?searchId=${op.searchId}&quotationId=${op.quotationId}`, {
        headers: getHeaders(token)
      });
      const text = await r.text();
      let d;
      try { d = JSON.parse(text); } catch(e) { throw new Error('Error al obtener detalle'); }

      const q = d.quote;
      console.log('[Cotizacion] Quote keys:', Object.keys(q || {}).join(','));
      console.log('[Cotizacion] q.penalties:', JSON.stringify(q?.penalties || []).substring(0, 300));
      // Also check if penalties are in flightRates
      if (q?.flightRates?.[0]?.rules) {
        console.log('[Cotizacion] fare.rules:', JSON.stringify(q.flightRates[0].rules).substring(0, 300));
      }
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

      // Penalidades
      const penalties = q.penalties || [];
      console.log(`[Cotizacion] Penalties raw count: ${penalties.length}`, penalties.length ? JSON.stringify(penalties.slice(0, 3)) : 'none');
      // type: 0=cambio, 1=cancelacion/devolución. applicability: 0=antes, 1=durante
      const extractPen = (type, applicability) => {
        const p = penalties.find(pen => pen.type === type && pen.applicability === applicability);
        if (!p) return null;
        return { monto: p.amount || p.penaltyAmount || 0, moneda: p.currency || p.penaltyCurrency || 'USD', permite: !!p.enabled };
      };
      const penalidades = {
        cambio_antes: extractPen(0, 0),
        cambio_durante: extractPen(0, 1),
        devolucion_antes: extractPen(1, 0),
        devolucion_durante: extractPen(1, 1),
        // Compatibilidad
        cambio: extractPen(0, 0),
        cancelacion: extractPen(1, 0)
      };
      console.log(`[Cotizacion] Penalidades: ${JSON.stringify(penalidades)}`);

      // Equipaje - intentar desde API, sino usar lo que mandó el frontend
      const bagLeg = q.legsWithBaggageAllowance?.[0]?.baggageAllowance 
                  || d.legsWithBaggageAllowance?.[0]?.baggageAllowance;
      let equipaje = op.equipaje || null; // Fallback del frontend
      if (bagLeg) {
        const handOnList = bagLeg.handOn || [];
        const handOnIncluido = handOnList.some(b => b.chargeType === 1 && b.pieces >= 1);
        const handOnLabel = handOnIncluido ? 'Incluida' : (handOnList.length > 0 ? 'Con cargo' : 'No informado');

        const carryOnList = bagLeg.carryOn || [];
        const carryOnItem = carryOnList.find(b => b.chargeType === 1 && b.pieces >= 1);
        const carryOnIncluido = !!carryOnItem;
        const carryOnLabel = carryOnItem 
          ? (`${carryOnItem.weight||''}${carryOnItem.weightUnit||''}`).trim() || 'Incluido' 
          : (carryOnList.length > 0 ? 'Con cargo' : 'No incluido');

        const checkedList = (bagLeg.checked || []).filter(b => b.passengerType === 0);
        const checkedIncluidos = checkedList.filter(b => b.chargeType === 1 && b.pieces > 0);
        const totalPieces = checkedIncluidos.reduce((sum, b) => sum + b.pieces, 0);
        const checkedIncluido = totalPieces > 0;
        const checkedRef = checkedIncluidos[0];
        const checkedLabel = checkedIncluido
          ? (checkedRef.weight && checkedRef.weight !== '0' && checkedRef.weight !== '' && checkedRef.weight !== null
              ? `${totalPieces}x ${checkedRef.weight}${checkedRef.unit || 'KG'}`
              : `${totalPieces}x 23KG`)
          : 'No incluida';

        equipaje = {
          handOn: { label: handOnLabel, incluido: handOnIncluido },
          carryOn: { label: carryOnLabel, incluido: carryOnIncluido },
          checked: { label: checkedLabel, incluido: checkedIncluido }
        };
      }

      return {
        aerolinea: d.airlinesDictionary?.[q.validatingCarrier] || q.validatingCarrier,
        vuelos, detalle_vuelo: detalle, pasajeros, penalidades, equipaje
      };
    }));

    const pdfBuffer = await generarPDFBuffer(opcionesCompletas, vendedor || 'guido', nombreCliente || '');
    console.log('[Cotizacion] Opciones:', JSON.stringify(opcionesCompletas.map(o => ({
      aerolinea: o.aerolinea,
      vuelos: o.vuelos.length,
      pasajeros: o.pasajeros.map(p => `${p.cantidad}x ${p.tipo} neto=${p.neto}`),
      penalidades: o.penalidades
    }))));
    res.set({ 'Content-Type': 'application/pdf', 'Content-Disposition': 'attachment; filename="cotizacion_lucky_tour.pdf"' });
    res.send(pdfBuffer);
  } catch(e) {
    console.error('[Cotizacion] Error:', e.message);
    res.status(500).json({ ok: false, error: e.message });
  }
});

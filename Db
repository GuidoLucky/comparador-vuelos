const Database = require('better-sqlite3');
const path = require('path');
const fs = require('fs');

const DATA_DIR = process.env.RAILWAY_VOLUME_MOUNT_PATH || '/data';
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new Database(path.join(DATA_DIR, 'luckytour.db'));

db.exec(`
  CREATE TABLE IF NOT EXISTS clientes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    apellido TEXT NOT NULL,
    nombre TEXT NOT NULL,
    email TEXT,
    telefono TEXT,
    genero INTEGER,
    fecha_nac_dia INTEGER,
    fecha_nac_mes INTEGER,
    fecha_nac_anio INTEGER,
    doc_pais TEXT,
    doc_pais_id TEXT,
    doc_tipo TEXT,
    doc_tipo_id TEXT,
    doc_numero TEXT,
    doc_venc_dia INTEGER,
    doc_venc_mes INTEGER,
    doc_venc_anio INTEGER,
    nacionalidad TEXT,
    nacionalidad_id TEXT,
    fact_pais TEXT,
    fact_pais_id TEXT,
    fact_tipo TEXT,
    fact_tipo_id TEXT,
    fact_numero TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS reservas (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pnr TEXT,
    order_id TEXT,
    order_number INTEGER,
    source INTEGER,
    search_id TEXT,
    quotation_id TEXT,
    tipo_viaje TEXT,
    origen TEXT,
    destino TEXT,
    fecha_salida TEXT,
    fecha_regreso TEXT,
    aerolinea TEXT,
    precio_usd REAL,
    precio_ars REAL,
    moneda TEXT,
    adultos INTEGER,
    ninos INTEGER,
    infantes INTEGER,
    estado TEXT DEFAULT 'CREADA',
    itinerario_json TEXT,
    pasajeros_json TEXT,
    contacto_json TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  );

  CREATE TABLE IF NOT EXISTS reserva_pasajeros (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    reserva_id INTEGER REFERENCES reservas(id),
    cliente_id INTEGER REFERENCES clientes(id),
    tipo TEXT,
    apellido TEXT,
    nombre TEXT,
    email TEXT
  );
`);

module.exports = db;

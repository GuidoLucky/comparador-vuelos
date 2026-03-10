const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL?.includes('railway') ? { rejectUnauthorized: false } : false
});

async function init() {
  // ── Empresas (tenants) ──────────────────────────────────────
  await pool.query(`
    CREATE TABLE IF NOT EXISTS empresas (
      id SERIAL PRIMARY KEY,
      nombre TEXT NOT NULL,
      dominio TEXT,
      activo BOOLEAN DEFAULT true,
      created_at TIMESTAMPTZ DEFAULT NOW()
    );
  `);

  // Empresa por defecto (Lucky Tour)
  await pool.query(`
    INSERT INTO empresas (id, nombre, dominio, activo)
    VALUES (1, 'Lucky Tour', 'comparador-vuelos-production.up.railway.app', true)
    ON CONFLICT (id) DO NOTHING;
  `);

  // ── Clientes ────────────────────────────────────────────────
  await pool.query(`
    CREATE TABLE IF NOT EXISTS clientes (
      id SERIAL PRIMARY KEY,
      empresa_id INTEGER REFERENCES empresas(id) DEFAULT 1,
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
      created_at TIMESTAMP DEFAULT NOW(),
      updated_at TIMESTAMP DEFAULT NOW()
    );
  `);

  // ── Reservas ────────────────────────────────────────────────
  await pool.query(`
    CREATE TABLE IF NOT EXISTS reservas (
      id SERIAL PRIMARY KEY,
      empresa_id INTEGER REFERENCES empresas(id) DEFAULT 1,
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
      aerolinea TEXT,
      precio_usd REAL,
      moneda TEXT,
      adultos INTEGER,
      ninos INTEGER,
      infantes INTEGER,
      estado TEXT DEFAULT 'CREADA',
      itinerario_json TEXT,
      pasajeros_json TEXT,
      contacto_json TEXT,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS reserva_pasajeros (
      id SERIAL PRIMARY KEY,
      reserva_id INTEGER REFERENCES reservas(id),
      cliente_id INTEGER REFERENCES clientes(id),
      tipo TEXT,
      apellido TEXT,
      nombre TEXT,
      email TEXT
    );
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS config (
      clave TEXT PRIMARY KEY,
      valor TEXT,
      updated_at TIMESTAMP DEFAULT NOW()
    );
  `);

  // ── Migraciones seguras (idempotentes) ──────────────────────
  // Agregar empresa_id a tablas existentes si no tienen
  await pool.query(`ALTER TABLE clientes  ADD COLUMN IF NOT EXISTS empresa_id INTEGER REFERENCES empresas(id) DEFAULT 1`);
  await pool.query(`ALTER TABLE reservas  ADD COLUMN IF NOT EXISTS empresa_id INTEGER REFERENCES empresas(id) DEFAULT 1`);

  // Asignar empresa 1 a registros históricos que no tengan empresa_id
  await pool.query(`UPDATE clientes SET empresa_id=1 WHERE empresa_id IS NULL`);
  await pool.query(`UPDATE reservas SET empresa_id=1 WHERE empresa_id IS NULL`);

  console.log('[DB] PostgreSQL listo');
}

init().catch(e => console.error('[DB] Error init:', e.message));

module.exports = {
  query: (text, params) => pool.query(text, params),
  pool
};

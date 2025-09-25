// server.js
require('dotenv').config();
const express = require('express');
const mysql = require('mysql2/promise');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcrypt');

const app = express();
app.use(cors());
app.use(bodyParser.json());

// Pool de conexiones
const pool = mysql.createPool({
  host: process.env.DB_HOST || '127.0.0.1',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD || '',
  database: process.env.DB_NAME || 'railway',
  port: Number(process.env.DB_PORT || 3306),
  waitForConnections: true,
  connectionLimit: 10
});

// UTIL: safe query wrapper
async function query(sql, params = []) {
  const [rows] = await pool.execute(sql, params);
  return rows;
}

/* ========== RUTAS ========== */

// Crear libro
app.post("/libros", async (req, res) => {
  try {
    const { titulo, autor, anio, usuarioId } = req.body;
    const sql = "INSERT INTO libros (titulo, autor, anio, usuario_id) VALUES (?, ?, ?, ?)";
    const result = await query(sql, [titulo, autor, anio, usuarioId || null]);
    res.json({ id: result.insertId, titulo, autor, anio, usuarioId: usuarioId || null });
  } catch (err) {
    console.error("❌ Error al crear libro:", err);
    res.status(500).json({ mensaje: "Error al crear libro" });
  }
});

// Leer libros (opcional ?usuarioId=)
app.get("/libros", async (req, res) => {
  try {
    const usuarioId = req.query.usuarioId;
    let sql = "SELECT * FROM libros";
    const params = [];
    if (usuarioId) {
      sql += " WHERE usuario_id = ?";
      params.push(usuarioId);
    }
    const rows = await query(sql, params);
    res.json(rows);
  } catch (err) {
    console.error("❌ Error al obtener libros:", err);
    res.status(500).json({ mensaje: "Error al obtener libros" });
  }
});

// Actualizar libro
app.put("/libros/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const { titulo, autor, anio, usuarioId } = req.body;

    if (usuarioId) {
      const rows = await query("SELECT usuario_id FROM libros WHERE id = ?", [id]);
      if (rows.length === 0) return res.status(404).json({ mensaje: "Libro no encontrado" });
      if (Number(rows[0].usuario_id) !== Number(usuarioId)) {
        return res.status(403).json({ mensaje: "No autorizado para actualizar este libro" });
      }
    }

    await query("UPDATE libros SET titulo=?, autor=?, anio=? WHERE id=?", [titulo, autor, anio, id]);
    res.json({ mensaje: "Libro actualizado" });
  } catch (err) {
    console.error("❌ Error al actualizar libro:", err);
    res.status(500).json({ mensaje: "Error al actualizar libro" });
  }
});

// Eliminar libro (mejor con usuarioId en body)
app.delete("/libros/:id", async (req, res) => {
  try {
    const { id } = req.params;
    const { usuarioId } = req.body; // ← ahora en body, no query
    if (!usuarioId) return res.status(400).json({ mensaje: "Se requiere usuarioId para eliminar" });

    const rows = await query("SELECT usuario_id FROM libros WHERE id = ?", [id]);
    if (rows.length === 0) return res.status(404).json({ mensaje: "Libro no encontrado" });
    if (Number(rows[0].usuario_id) !== Number(usuarioId)) {
      return res.status(403).json({ mensaje: "No autorizado para eliminar este libro" });
    }

    await query("DELETE FROM libros WHERE id = ?", [id]);
    res.json({ mensaje: "Libro eliminado" });
  } catch (err) {
    console.error("❌ Error al eliminar libro:", err);
    res.status(500).json({ mensaje: "Error al eliminar libro" });
  }
});

/* ========== AUTENTICACIÓN ========== */

// Registro
app.post("/usuarios/registro", async (req, res) => {
  try {
    const { correo, contrasena, nombre } = req.body;
    if (!correo || !contrasena) return res.status(400).json({ mensaje: "Correo y contraseña son obligatorios" });

    const existing = await query("SELECT id FROM usuarios WHERE correo = ?", [correo]);
    if (existing.length > 0) return res.status(409).json({ mensaje: "El correo ya está registrado" });

    const hash = await bcrypt.hash(contrasena, 10);
    const result = await query("INSERT INTO usuarios (correo, contrasena, nombre) VALUES (?, ?, ?)", [correo, hash, nombre || null]);
    res.json({ mensaje: "Usuario registrado correctamente", id: result.insertId });
  } catch (err) {
    console.error("❌ Error en registro:", err);
    res.status(500).json({ mensaje: "Error en el registro" });
  }
});

// Login
app.post("/usuarios/login", async (req, res) => {
  try {
    const { correo, contrasena } = req.body;
    if (!correo || !contrasena) return res.status(400).json({ mensaje: "Correo y contraseña son obligatorios" });

    const rows = await query("SELECT id, correo, nombre, contrasena FROM usuarios WHERE correo = ?", [correo]);
    if (rows.length === 0) return res.status(401).json({ mensaje: "Correo o contraseña incorrectos" });

    const user = rows[0];
    const ok = await bcrypt.compare(contrasena, user.contrasena);
    if (!ok) return res.status(401).json({ mensaje: "Correo o contraseña incorrectos" });

    delete user.contrasena;
    res.json({ mensaje: "Login exitoso", usuario: user });
  } catch (err) {
    console.error("❌ Error en login:", err);
    res.status(500).json({ mensaje: "Error en el login" });
  }
});

/* ========== INICIAR SERVIDOR ========== */
const PORT = process.env.PORT || 3000;
app.listen(PORT, async () => {
  try {
    await pool.query("SELECT 1");
    console.log(`✅ Servidor corriendo en http://localhost:${PORT} (DB conectada)`);
  } catch (err) {
    console.error("❌ Servidor corriendo pero SIN conexión a DB:", err);
  }
});

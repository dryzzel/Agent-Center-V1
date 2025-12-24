import express from "express";
import cors from "cors";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import fs from "fs-extra";
import dotenv from "dotenv";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import multer from "multer";
import csv from "csv-parser";
import { MongoClient, ObjectId } from "mongodb";
import { SDK } from "@ringcentral/sdk";
import path from 'path';
import { fileURLToPath } from 'url';
import { randomUUID } from "crypto";


const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// ==========================================
// CONFIGURACIÓN DEL SERVIDOR (BACKEND)
// ==========================================
// Este archivo maneja la lógica del servidor, incluyendo:
// 1. Conexión a Base de Datos (MongoDB)
// 2. Autenticación y Seguridad (JWT, Bcrypt, Helmet)
// 3. Rutas de API para Admin y Agentes
// 4. Integración con RingCentral y WebSockets (Socket.io)
// ==========================================

// Cargar variables de entorno
dotenv.config();

import { createServer } from "http";
import { Server } from "socket.io";

const app = express();
app.use(express.static(__dirname)); // Serve frontend files
const httpServer = createServer(app);
// Configuración de Socket.io para comunicación en tiempo real (ej. actualizar dashboard de admin cuando un agente hace una venta).
const io = new Server(httpServer, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"]
  }
});

const PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET;
const MONGO_URI = process.env.MONGO_URI || process.env.MONGO_URL || "mongodb://localhost:27017";
console.log("DEBUG: Using MONGO_URI:", MONGO_URI.includes("localhost") ? "Localhost (Default)" : "Remote URI (Masked)");

const DB_NAME = "call-center";

// Initialize RingCentral SDK
const rcsdk = new SDK({
  server: process.env.RC_SERVER_URL,
  clientId: process.env.RC_CLIENT_ID,
  clientSecret: process.env.RC_CLIENT_SECRET
});
const platform = rcsdk.platform();

let db;

// Establece la conexión con la base de datos MongoDB.
// Esencial para el funcionamiento de la app, se ejecuta al inicio.
async function connectDB() {
  try {
    const client = new MongoClient(MONGO_URI);
    await client.connect();
    db = client.db(DB_NAME);
    console.log("🚀 Conectado a MongoDB");
  } catch (err) {
    console.error("Error conectando a MongoDB:", err);
    process.exit(1);
  }
}

// --- Middlewares de Seguridad y Configuración ---
// Helmet para headers de seguridad, CORS para permitir peticiones cruzadas,
// y Express.json para parsear bodies de requests.
app.use(helmet());
app.use(cors({ origin: "*", methods: ["GET", "POST", "PUT", "DELETE"], allowedHeaders: ["Content-Type", "Authorization"] }));
app.use(express.json());

// Limitador de tasa para el login.
// Previene ataques de fuerza bruta limitando los intentos fallidos desde una misma IP.
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 10, // Limita cada IP a 10 peticiones por ventana
  message: "Demasiados intentos de inicio de sesión, por favor intente de nuevo en 15 minutos",
});

const upload = multer({ dest: 'uploads/' });

// ==========================================
// AUTENTICACIÓN Y SEGURIDAD
// ==========================================
// Manejo de inicio de sesión y generación de Tokens JWT.
// Se usa rateLimit para prevenir ataques de fuerza bruta.

app.post("/auth/login", loginLimiter, async (req, res) => {
  const { username, password } = req.body;
  const users = await db.collection("users").find().toArray();
  const user = users.find((u) => u.username === username);
  if (!user) return res.status(401).json({ success: false, error: "Usuario no encontrado" });

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(401).json({ success: false, error: "Contraseña incorrecta" });

  // Generate and store session ID to enforce single session
  const sessionId = randomUUID();
  await db.collection("users").updateOne(
    { _id: user._id },
    { $set: { sessionId: sessionId } }
  );

  const token = jwt.sign({ id: user._id, role: user.role, sessionId }, SECRET, { expiresIn: "7d" });
  res.json({
    success: true,
    user: { id: user._id, username: user.username, email: user.email, role: user.role },
    token
  });
});

// Middlewares de autenticación
// Middleware de autenticación para Administradores.
// Verifica que el token JWT sea válido y que el rol sea 'admin'.
const authAdmin = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: "Falta token" });

  try {
    const token = authHeader.split(" ")[1];
    const decoded = jwt.verify(token, SECRET);
    if (decoded.role !== "admin") return res.status(403).json({ error: "No autorizado" });

    // Verify session ID matches the one in DB
    const user = await db.collection("users").findOne({ _id: new ObjectId(decoded.id) });
    if (!user || user.sessionId !== decoded.sessionId) {
      return res.status(401).json({ error: "Sesión expirada. Se ha iniciado sesión en otro dispositivo." });
    }

    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: "Token inválido" });
  }
};

// Middleware de autenticación para Agentes.
// Verifica que el token JWT sea válido y que el rol sea 'agent'.
const authAgent = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ error: "Falta token" });

  try {
    const token = authHeader.split(" ")[1];
    const decoded = jwt.verify(token, SECRET);
    if (decoded.role !== "agent") return res.status(403).json({ error: "No autorizado" });

    // Verify session ID matches the one in DB
    const user = await db.collection("users").findOne({ _id: new ObjectId(decoded.id) });
    if (!user || user.sessionId !== decoded.sessionId) {
      return res.status(401).json({ error: "Sesión expirada. Se ha iniciado sesión en otro dispositivo." });
    }

    req.user = decoded;
    next();
  } catch (err) {
    res.status(401).json({ error: "Token inválido" });
  }
};


// ==========================================
// RUTAS DE ADMINISTRACIÓN
// ==========================================
// Endpoints protegidos para gestión de usuarios, leads y estadísticas globales.
// Requieren token con rol de 'admin'.

app.post("/auth/register", authAdmin, async (req, res) => {
  const { username, password, email } = req.body;
  if (!username || !password) return res.status(400).json({ error: "Username and password are required" });

  const existingUser = await db.collection("users").findOne({ username });
  if (existingUser) return res.status(400).json({ error: "Usuario ya existe" });

  const hashed = await bcrypt.hash(password, 10);
  const newUser = {
    username,
    password: hashed,
    email: email || "", // Optional email
    role: "agent",
    stats: {},
    lastActivity: new Date().toISOString()
  };

  await db.collection("users").insertOne(newUser);

  res.json({ success: true, message: "Usuario creado exitosamente" });
});

// Obtener lista de usuarios con progreso y estadísticas diarias.
// IMPORTANTE: Las estadísticas se calculan en tiempo real basándose en el día actual (UTC-4).
app.get("/admin/users", authAdmin, async (req, res) => {
  const users = await db.collection("users").find().toArray();

  // Calculate start of day in UTC-4
  const now = new Date();
  const utc4Offset = -4 * 60;
  const localNow = new Date(now.getTime() + (utc4Offset * 60 * 1000));
  localNow.setUTCHours(0, 0, 0, 0);
  const startOfDay = new Date(localNow.getTime() - (utc4Offset * 60 * 1000));

  const usersWithProgress = await Promise.all(users.map(async (user) => {
    const assignedLeads = await db.collection("leads").countDocuments({ assignedTo: user._id });
    const completedLeadsFromDB = await db.collection("leads").countDocuments({ assignedTo: user._id, DISPOSITION: { $ne: null } });

    // Calculate Daily Stats (Today only, reset at 4 AM UTC)
    const dailyStatsAgg = await db.collection("leads").aggregate([
      {
        $match: {
          assignedTo: user._id,
          Timestamp: { $gte: startOfDay.toISOString() },
          DISPOSITION: { $ne: null }
        }
      },
      { $group: { _id: "$DISPOSITION", count: { $sum: 1 } } }
    ]).toArray();

    const dailyStats = dailyStatsAgg.reduce((acc, curr) => {
      acc[curr._id] = curr.count;
      return acc;
    }, {});

    // Use stored stats heavily for progress calculation ONLY (cumulative)
    const accumulatedStats = user.stats || {};
    const statsSum = Object.values(accumulatedStats).reduce((a, b) => a + b, 0);

    // Determine the most accurate 'completed' count for Progress Bar
    const completedLeads = Math.max(completedLeadsFromDB, statsSum, user.progress?.currentIndex || 0);

    return {
      id: user._id,
      username: user.username,
      email: user.email,
      stats: dailyStats, // Return DAILY stats for the dashboard view
      lastActivity: user.lastActivity,
      progress: {
        currentIndex: completedLeads,
        total: assignedLeads,
      },
      role: user.role,
      filename: assignedLeads > 0 ? `Leads asignados: ${assignedLeads}` : 'Sin leads',
    };
  }));

  res.json(usersWithProgress);
});

// Obtener estadísticas globales de disposiciones del día actual (UTC-4).
app.get("/admin/stats", authAdmin, async (req, res) => {
  try {
    // Calculate start of day in UTC-4
    const now = new Date();
    // Adjust to UTC-4
    const utc4Offset = -4 * 60; // -4 hours in minutes
    const localNow = new Date(now.getTime() + (utc4Offset * 60 * 1000));
    localNow.setUTCHours(0, 0, 0, 0);
    // Convert back to UTC for query
    const startOfDay = new Date(localNow.getTime() - (utc4Offset * 60 * 1000));

    const dispositionCounts = await db.collection("leads").aggregate([
      {
        $match: {
          DISPOSITION: { $ne: null },
          Timestamp: { $gte: startOfDay.toISOString() }
        }
      },
      { $group: { _id: "$DISPOSITION", count: { $sum: 1 } } }
    ]).toArray();

    const stats = dispositionCounts.reduce((acc, item) => {
      acc[item._id] = item.count;
      return acc;
    }, {});

    res.json(stats);
  } catch (err) {
    console.error("Error getting stats:", err);
    res.status(500).json({ error: "Error al obtener las estadísticas" });
  }
});

app.put("/admin/users/:id", authAdmin, async (req, res) => {
  const { id } = req.params;
  const { email, role, username, password, rcExtensionId } = req.body;

  if (!role || !username) {
    return res.status(400).json({ error: "Role and Username are required" });
  }

  try {
    if (!ObjectId.isValid(id)) {
      return res.status(400).json({ error: "ID de usuario inválido" });
    }
    const userToUpdate = await db.collection("users").findOne({ _id: new ObjectId(id) });

    if (!userToUpdate) {
      return res.status(404).json({ error: "Usuario no encontrado" });
    }

    // No permitir cambiar el rol o email del admin principal
    if (userToUpdate.username === 'admin' && username !== 'admin') {
      return res.status(403).json({ error: "Cannot change username of the main admin" });
    }

    // Check for username uniqueness if changed
    if (username !== userToUpdate.username) {
      const existing = await db.collection("users").findOne({ username });
      if (existing) return res.status(400).json({ error: "Username already taken" });
    }

    const updateFields = { email, role, username, rcExtensionId };
    if (password) {
      updateFields.password = await bcrypt.hash(password, 10);
    }

    await db.collection("users").updateOne({ _id: new ObjectId(id) }, { $set: updateFields });
    res.json({ success: true, message: "Usuario actualizado correctamente" });
  } catch (err) {
    console.error("Error updating user:", err);
    res.status(500).json({ error: "Error al actualizar el usuario" });
  }
});

// Obtener estadísticas de un usuario específico en un rango de fechas.
app.get("/admin/users/:id/stats", authAdmin, async (req, res) => {
  const { id } = req.params;
  const { startDate, endDate } = req.query;

  if (!startDate || !endDate) {
    return res.status(400).json({ error: "Busqueda de fechas requerida" });
  }

  try {
    if (!ObjectId.isValid(id)) {
      return res.status(400).json({ error: "ID de usuario inválido" });
    }

    // Convert dates to ISO strings for comparison
    const start = new Date(startDate);
    const end = new Date(endDate);
    end.setUTCHours(23, 59, 59, 999); // Include the whole end day

    const stats = await db.collection("leads").aggregate([
      {
        $match: {
          assignedTo: new ObjectId(id),
          DISPOSITION: { $ne: null },
          Timestamp: {
            $gte: start.toISOString(),
            $lte: end.toISOString()
          }
        }
      },
      {
        $group: {
          _id: "$DISPOSITION",
          count: { $sum: 1 }
        }
      }
    ]).toArray();

    const dispositions = stats.reduce((acc, item) => {
      acc[item._id] = item.count;
      return acc;
    }, {});

    const totalCalled = Object.values(dispositions).reduce((a, b) => a + b, 0);

    // Calculate Contact Rate (excluding NA, VM, DC, WN)
    const nonContactDispos = ['NA', 'VM', 'DC', 'WN'];
    const totalContacts = Object.entries(dispositions)
      .filter(([key]) => !nonContactDispos.includes(key))
      .reduce((sum, [, value]) => sum + value, 0);

    const contactRate = totalCalled > 0 ? (totalContacts / totalCalled) * 100 : 0;

    // Calculate Lead Conversion (FUTURE, ND/SD) -> These are "Leads"
    const leadDispos = ['FUTURE', 'ND/SD'];
    const totalLeads = Object.entries(dispositions)
      .filter(([key]) => leadDispos.includes(key))
      .reduce((sum, [, value]) => sum + value, 0);

    const leadConversionRate = totalContacts > 0 ? (totalLeads / totalContacts) * 100 : 0;

    res.json({
      totalCalls: totalCalled,
      contactRate,
      leadConversionRate,
      dispositions
    });

  } catch (err) {
    console.error("Error getting user stats:", err);
    res.status(500).json({ error: "Error al obtener estadísticas del usuario" });
  }
});

app.delete("/admin/users/:id", authAdmin, async (req, res) => {
  const { id } = req.params;

  try {
    if (!ObjectId.isValid(id)) {
      return res.status(400).json({ error: "ID de usuario inválido" });
    }
    const userToDelete = await db.collection("users").findOne({ _id: new ObjectId(id) });

    if (!userToDelete) {
      return res.status(404).json({ error: "Usuario no encontrado" });
    }

    if (userToDelete.role === 'admin') {
      return res.status(400).json({ error: "No se puede eliminar a un administrador" });
    }

    await db.collection("users").deleteOne({ _id: new ObjectId(id) });

    // Opcional: Desasignar leads del usuario eliminado
    await db.collection("leads").updateMany({ assignedTo: new ObjectId(id) }, { $set: { assignedTo: null } });

    res.json({ success: true, message: "Usuario eliminado correctamente" });
  } catch (err) {
    console.error("Error deleting user:", err);
    res.status(500).json({ error: "Error al eliminar el usuario" });
  }
});

// Bulk Delete Leads
app.delete("/admin/leads/bulk", authAdmin, async (req, res) => {
  const { leadIds, password } = req.body;

  if (!leadIds || !Array.isArray(leadIds) || !leadIds.length) {
    return res.status(400).json({ error: "No leads selected for deletion." });
  }

  if (!password) {
    return res.status(400).json({ error: "Password is required." });
  }

  try {
    const admin = await db.collection("users").findOne({ _id: new ObjectId(req.user.id) });
    const isMatch = await bcrypt.compare(password, admin.password);
    if (!isMatch) {
      return res.status(401).json({ error: "Incorrect password." });
    }
    const objectIds = leadIds.map(id => new ObjectId(id));
    const result = await db.collection("leads").deleteMany({ _id: { $in: objectIds } });

    res.json({ success: true, message: `Successfully deleted ${result.deletedCount} leads.` });
  } catch (err) {
    console.error("Error deleting leads:", err);
    res.status(500).json({ error: "Failed to delete leads." });
  }
});

// Carga masiva de leads desde un archivo CSV.
// Parsea el archivo, asigna campos por defecto y guarda en la base de datos.
app.post("/admin/upload", authAdmin, upload.single('file'), async (req, res) => {
  const { listName, customId } = req.body;

  if (!req.file || !listName || !customId) {
    return res.status(400).json({ error: "Faltan datos (archivo, nombre de lista o Custom ID)" });
  }

  const filePath = req.file.path;
  const results = [];

  fs.createReadStream(filePath)
    .pipe(csv())
    .on('data', (data) => {
      // Ensure essential fields exist or provide defaults
      results.push({
        ...data,
        listName,
        customId,
        assignedTo: null,
        Timestamp: new Date().toISOString(),
        DISPOSITION: null // Default disposition
      });
    })
    .on('end', async () => {
      try {
        if (results.length > 0) {
          await db.collection("leads").insertMany(results);
        }
        fs.unlink(filePath, (err) => {
          if (err) console.error("Error deleting temp file:", err);
        });
        res.json({ success: true, message: `${results.length} leads subidos a la lista '${listName}'` });
      } catch (err) {
        console.error("Error inserting leads:", err);
        res.status(500).json({ error: "Error al guardar los leads en la base de datos" });
      }
    })
    .on('error', (err) => {
      console.error("Error parsing CSV:", err);
      res.status(500).json({ error: "Error al procesar el archivo CSV" });
    });
});

app.get("/admin/leads/unassigned", authAdmin, async (req, res) => {
  try {
    const unassignedLeads = await db.collection("leads").find({ assignedTo: null }).toArray();
    res.json(unassignedLeads);
  } catch (err) {
    console.error("Error loading unassigned leads:", err);
    res.status(500).json({ error: "Error al cargar los leads no asignados" });
  }
});

app.post("/admin/assign", authAdmin, async (req, res) => {
  const { userId, leadsToAssign } = req.body;

  if (!userId || !leadsToAssign || !leadsToAssign.length) {
    return res.status(400).json({ error: "Datos incompletos para la asignación" });
  }

  try {
    const leadIds = leadsToAssign.map(id => new ObjectId(id));

    await db.collection("leads").updateMany(
      { _id: { $in: leadIds } },
      { $set: { assignedTo: new ObjectId(userId) } }
    );

    res.json({ success: true, message: "Leads asignados correctamente." });

  } catch (err) {
    console.error("Error assigning leads:", err);
    res.status(500).json({ error: "Error al asignar los leads." });
  }
});

// Obtiene opciones únicas para filtros (Productos y Compañías Anteriores)
app.get("/admin/filters/options", authAdmin, async (req, res) => {
  try {
    const products = await db.collection("leads").distinct("Product");
    const companies = await db.collection("leads").distinct("Prev. Company");
    const customIds = await db.collection("leads").distinct("customId");
    const listNames = await db.collection("leads").distinct("listName");

    // Filter out null/empty values and sort
    const cleanProducts = products.filter(p => p).sort();
    const cleanCompanies = companies.filter(c => c).sort();
    const cleanCustomIds = customIds.filter(c => c).sort();
    const cleanListNames = listNames.filter(l => l).sort();

    res.json({
      products: cleanProducts,
      companies: cleanCompanies,
      customIds: cleanCustomIds,
      listNames: cleanListNames
    });
  } catch (err) {
    console.error("Error fetching filter options:", err);
    res.status(500).json({ error: "Error al obtener opciones de filtro" });
  }
});

// Endpoint principal para obtener leads con filtros avanzados.
// Soporta filtrado por disposición, agente, producto, fecha, búsqueda de texto y ordenamiento.
app.get("/admin/leads", authAdmin, async (req, res) => {
  const { disposition, assignedTo, product, sortBy, sortOrder, startDate, endDate, search, listName, prevCompany, customId } = req.query;
  const query = {};

  if (disposition) {
    if (Array.isArray(disposition)) {
      query.DISPOSITION = { $in: disposition };
    } else {
      query.DISPOSITION = disposition;
    }
  }
  if (assignedTo) {
    if (assignedTo === 'unassigned') {
      query.assignedTo = null;
    } else if (ObjectId.isValid(assignedTo)) {
      query.assignedTo = new ObjectId(assignedTo);
    } else {
      return res.json([]);
    }
  }
  if (product) query.Product = product;
  if (listName) query.listName = listName;
  if (prevCompany) query['Prev. Company'] = prevCompany;
  if (customId) query.customId = customId;

  // Date Range Filter
  if (startDate || endDate) {
    query.Timestamp = {};
    if (startDate) {
      const start = new Date(startDate);
      query.Timestamp.$gte = start.toISOString();
    }
    if (endDate) {
      const end = new Date(endDate);
      end.setUTCHours(23, 59, 59, 999);
      query.Timestamp.$lte = end.toISOString();
    }
  }

  // Search Filter (Name or Phone)
  if (search) {
    const searchRegex = { $regex: search, $options: 'i' };
    query.$or = [
      { Name: searchRegex },
      { Phone: searchRegex }
    ];
  }

  const sortOptions = {};
  if (sortBy === 'date') {
    sortOptions['Timestamp'] = sortOrder === 'asc' ? 1 : -1;
  } else {
    // Default sort: newest first
    sortOptions['Timestamp'] = -1;
  }

  try {
    const leads = await db.collection("leads").aggregate([
      { $match: query },
      { $sort: sortOptions },
      {
        $lookup: {
          from: "users",
          localField: "assignedTo",
          foreignField: "_id",
          as: "agent"
        }
      },
      {
        $unwind: {
          path: "$agent",
          preserveNullAndEmptyArrays: true
        }
      },
      {
        $project: {
          "agent.password": 0, // Excluir el password del agente
          "agent.stats": 0,
          "agent.lastActivity": 0,
          "agent.email": 0,
          "agent.role": 0,
        }
      }
    ]).toArray();
    res.json(leads);
  } catch (err) {
    console.error("Error loading leads for admin:", err);
    res.status(500).json({ error: "Error al cargar los leads" });
  }
});

// Reasigna un conjunto de leads a un nuevo agente.
// Útil para redistribuir carga de trabajo o mover leads de agentes inactivos.
app.post("/admin/leads/reassign", authAdmin, async (req, res) => {
  const { leadIds, newUserId } = req.body;

  if (!leadIds || !Array.isArray(leadIds) || leadIds.length === 0 || !newUserId) {
    return res.status(400).json({ error: "Datos incompletos para la asignación" });
  }

  try {
    const objectLeadIds = leadIds.map(id => new ObjectId(id));
    let objectNewUserId = null;

    if (newUserId !== 'unassigned') {
      if (!ObjectId.isValid(newUserId)) {
        return res.status(400).json({ error: "ID de usuario inválido" });
      }
      objectNewUserId = new ObjectId(newUserId);
    }

    await db.collection("leads").updateMany(
      { _id: { $in: objectLeadIds } },
      { $set: { assignedTo: objectNewUserId } }
    );

    res.json({ success: true, message: "Leads reasignados correctamente." });
  } catch (err) {
    console.error("Error reassigning leads:", err);
    res.status(500).json({ error: "Error al reasignar los leads." });
  }
});

// Actualiza un lead específico. Si cambia la disposición, registra el cambio en el historial.
app.put("/admin/leads/:id", authAdmin, async (req, res) => {
  const { id } = req.params;
  const updateData = req.body;

  try {
    if (!ObjectId.isValid(id)) {
      return res.status(400).json({ error: "Invalid Lead ID" });
    }

    // Prepare update fields
    const updateFields = { ...updateData };
    if (updateFields._id) delete updateFields._id; // Don't try to update _id

    // If updating disposition, add history entry
    if (updateData.DISPOSITION) {
      const historyEntry = {
        action: 'Admin Update',
        disposition: updateData.DISPOSITION,
        note: 'Updated by Admin',
        agentId: new ObjectId(req.user.id),
        timestamp: new Date().toISOString()
      };

      await db.collection("leads").updateOne(
        { _id: new ObjectId(id) },
        {
          $set: updateFields,
          $push: { history: historyEntry }
        }
      );
    } else {
      await db.collection("leads").updateOne(
        { _id: new ObjectId(id) },
        { $set: updateFields }
      );
    }

    res.json({ success: true, message: "Lead updated successfully" });
  } catch (err) {
    console.error("Error updating lead:", err);
    res.status(500).json({ error: "Error updating lead" });
  }
});

// Vista previa de leads duplicados basándose en el número de teléfono.
app.post("/admin/leads/deduplicate/preview", authAdmin, async (req, res) => {
  try {
    // 1. Find all duplicates
    const duplicates = await db.collection("leads").aggregate([
      {
        $group: {
          _id: "$Phone",
          count: { $sum: 1 },
          ids: { $push: "$_id" },
          docs: { $push: "$$ROOT" } // Push entire doc to sort
        }
      },
      {
        $match: {
          count: { $gt: 1 }
        }
      }
    ]).toArray();

    if (duplicates.length === 0) {
      return res.json({ count: 0, duplicates: [] });
    }

    let idsToDelete = [];
    const previewData = [];

    // 2. Identify IDs to delete and prepare preview
    duplicates.forEach(group => {
      // Sort docs by Timestamp descending (newest first)
      const sortedDocs = group.docs.sort((a, b) => {
        const timeA = a.Timestamp ? new Date(a.Timestamp).getTime() : a._id.getTimestamp().getTime();
        const timeB = b.Timestamp ? new Date(b.Timestamp).getTime() : b._id.getTimestamp().getTime();
        return timeB - timeA; // Descending
      });

      // Keep the first one (index 0), delete the rest
      const toRemove = sortedDocs.slice(1);
      const toRemoveIds = toRemove.map(d => d._id);

      idsToDelete.push(...toRemoveIds);

      // Add to preview data
      previewData.push({
        phone: group._id,
        kept: sortedDocs[0],
        removed: toRemove
      });
    });

    res.json({
      count: idsToDelete.length,
      preview: previewData
    });

  } catch (err) {
    console.error("Error previewing duplicates:", err);
    res.status(500).json({ error: "Error al previsualizar duplicados" });
  }
});

// Elimina leads duplicados basándose en el número de teléfono.
// Mantiene el registro más reciente y elimina los antiguos.
app.post("/admin/leads/deduplicate", authAdmin, async (req, res) => {
  const { password } = req.body;

  if (!password) {
    return res.status(400).json({ error: "Password is required." });
  }

  try {
    const admin = await db.collection("users").findOne({ _id: new ObjectId(req.user.id) });
    const isMatch = await bcrypt.compare(password, admin.password);
    if (!isMatch) {
      return res.status(401).json({ error: "Incorrect password." });
    }

    // 1. Find all duplicates
    const duplicates = await db.collection("leads").aggregate([
      {
        $group: {
          _id: "$Phone",
          count: { $sum: 1 },
          ids: { $push: "$_id" },
          docs: { $push: "$$ROOT" } // Push entire doc to sort
        }
      },
      {
        $match: {
          count: { $gt: 1 }
        }
      }
    ]).toArray();

    if (duplicates.length === 0) {
      return res.json({ success: true, message: "No duplicate leads found.", count: 0 });
    }

    let totalDeleted = 0;
    const idsToDelete = [];

    // 2. Identify IDs to delete
    duplicates.forEach(group => {
      // Sort docs by Timestamp descending (newest first)
      const sortedDocs = group.docs.sort((a, b) => {
        const timeA = a.Timestamp ? new Date(a.Timestamp).getTime() : a._id.getTimestamp().getTime();
        const timeB = b.Timestamp ? new Date(b.Timestamp).getTime() : b._id.getTimestamp().getTime();
        return timeB - timeA; // Descending
      });

      // Keep the first one (index 0), delete the rest
      const toRemove = sortedDocs.slice(1).map(d => d._id);
      idsToDelete.push(...toRemove);
    });

    // 3. Delete them
    if (idsToDelete.length > 0) {
      const result = await db.collection("leads").deleteMany({
        _id: { $in: idsToDelete }
      });
      totalDeleted = result.deletedCount;
    }

    res.json({ success: true, message: `Successfully removed ${totalDeleted} duplicate leads.`, count: totalDeleted });

  } catch (err) {
    console.error("Error deduplicating leads:", err);
    res.status(500).json({ error: "Failed to deduplicate leads" });
  }
});

// Actualiza las estadísticas de la sesión actual del agente en la base de datos.
app.post("/agent/stats", authAgent, async (req, res) => {
  const { stats } = req.body;
  const userId = new ObjectId(req.user.id);

  if (!stats) {
    return res.status(400).json({ error: "Datos de estadísticas incompletos" });
  }

  try {
    await db.collection("users").updateOne(
      { _id: userId },
      { $set: { stats: stats, lastActivity: new Date().toISOString() } }
    );
    res.json({ success: true, message: "Estadísticas actualizadas correctamente" });
  } catch (err) {
    console.error("Error updating stats:", err);
    res.status(500).json({ error: "Error al actualizar las estadísticas" });
  }
});

// Endpoint faltante: Guarda el progreso del agente y actualiza el lead en la BD.
// Esto es CRÍTICO para que el historial y las estadísticas funcionen.
app.post("/agent/progress", authAgent, async (req, res) => {
  const { currentIndex, updatedRow, originalIndex } = req.body;
  const userId = new ObjectId(req.user.id);

  if (currentIndex === undefined || !updatedRow || !originalIndex) {
    return res.status(400).json({ error: "Datos de progreso incompletos" });
  }

  try {
    // 1. Update User Progress
    await db.collection("users").updateOne(
      { _id: userId },
      {
        $set: {
          "progress.currentIndex": currentIndex,
          lastActivity: new Date().toISOString()
        }
      }
    );

    // 2. Update Lead Data (Disposition, History, etc.)
    const leadId = new ObjectId(originalIndex);
    const timestamp = new Date().toISOString();

    const historyEntry = {
      action: "Call Result",
      disposition: updatedRow.DISPOSITION,
      note: updatedRow.notes,
      agentId: userId,
      timestamp: timestamp
    };

    const updateFields = {
      DISPOSITION: updatedRow.DISPOSITION,
      Timestamp: timestamp,
      notes: updatedRow.notes,
    };

    if (updatedRow.callback) {
      updateFields.callback = updatedRow.callback;
    }

    await db.collection("leads").updateOne(
      { _id: leadId },
      {
        $set: updateFields,
        $push: { history: historyEntry }
      }
    );

    res.json({ success: true, message: "Progreso y lead guardados correctamente" });

  } catch (err) {
    console.error("Error updating progress:", err);
    res.status(500).json({ error: "Error al guardar el progreso" });
  }
});


// Obtiene los datos iniciales para el agente (leads asignados).
app.get("/agent/data", authAgent, async (req, res) => {
  try {
    const userId = new ObjectId(req.user.id);
    const user = await db.collection("users").findOne({ _id: userId });

    // Fetch assigned leads, sorted if necessary (e.g. by Timestamp desc)
    // For now, default sort is fine or explicit sort by _id/Timestamp
    const leads = await db.collection("leads").find({ assignedTo: userId }).toArray();

    res.json({
      success: true,
      data: leads,
      currentIndex: user.progress?.currentIndex || 0
    });
  } catch (err) {
    console.error("Error loading agent data:", err);
    res.status(500).json({ error: "Error loading agent data" });
  }
});

// Obtiene la lista de callbacks pendientes para el agente, ordenados por fecha.
app.get("/agent/callbacks", authAgent, async (req, res) => {
  const userId = new ObjectId(req.user.id);

  try {
    const callbacks = await db.collection("leads").find({
      assignedTo: userId,
      callback: { $ne: null } // Check for the callback field
    }).sort({ callback: 1 }).toArray(); // Sort by callback

    res.json(callbacks.map(c => ({ ...c, originalIndex: c._id })));

  } catch (err) {
    console.error("Error loading callbacks:", err);
    res.status(500).json({ error: "Error al cargar los callbacks" });
  }
});

// Filtra los leads del agente por una disposición específica.
app.get("/agent/leads/by-disposition", authAgent, async (req, res) => {
  const userId = new ObjectId(req.user.id);
  const { disposition } = req.query;

  if (!disposition) {
    return res.status(400).json({ error: "Se requiere un parámetro 'disposition'" });
  }

  try {
    const leads = await db.collection("leads").find({
      assignedTo: userId,
      DISPOSITION: disposition
    }).toArray();
    res.json(leads);
  } catch (err) {
    console.error("Error loading leads by disposition:", err);
    res.status(500).json({ error: "Error al cargar los leads por disposición" });
  }
});

// Obtiene el historial de cambios de un lead específico.
app.get("/agent/leads/:id/history", authAgent, async (req, res) => {
  const { id } = req.params;
  try {
    if (!ObjectId.isValid(id)) return res.status(400).json({ error: "Invalid ID" });

    const lead = await db.collection("leads").findOne(
      { _id: new ObjectId(id) },
      { projection: { history: 1 } }
    );

    if (!lead) return res.status(404).json({ error: "Lead not found" });

    res.json(lead.history || []);
  } catch (err) {
    console.error("Error fetching lead history:", err);
    res.status(500).json({ error: "Error fetching history" });
  }
});

// ==========================================
// INTEGRACIÓN CON RINGCENTRAL
// ==========================================
// Obtención de métricas de llamadas desde la API de RingCentral.
app.get("/admin/ringcentral/stats", authAdmin, async (req, res) => {
  try {
    // 1. Authenticate with RingCentral
    if (!await platform.loggedIn()) {
      await platform.login({ jwt: process.env.RC_JWT });
    }

    // 2. Get all agents with an rcExtensionId
    const agents = await db.collection("users").find({
      role: 'agent',
      rcExtensionId: { $exists: true, $ne: "" }
    }).toArray();

    if (agents.length === 0) {
      return res.json({ global: {}, agents: [] });
    }

    // 2.5 Resolve Extension Numbers to RingCentral User IDs
    // The Analytics API expects internal User IDs, but users likely entered Extension Numbers (e.g. 101)
    let extensionMap = {};
    try {
      const extResp = await platform.get('/restapi/v1.0/account/~/extension', { perPage: 1000 });
      const extData = await extResp.json();
      if (extData.records) {
        extData.records.forEach(ext => {
          // Map extensionNumber to id (as string)
          extensionMap[String(ext.extensionNumber)] = String(ext.id);
        });
      }
    } catch (e) {
      console.error("Error fetching RC extensions:", e);
    }

    const validKeys = [];
    const keyToAgentMap = {};

    agents.forEach(agent => {
      const inputId = String(agent.rcExtensionId).trim();
      // Check if input is an extension number in our map
      const resolvedId = extensionMap[inputId];

      // Use resolved ID if found, otherwise assume input might be the ID itself
      const key = resolvedId || inputId;

      validKeys.push(key);
      keyToAgentMap[key] = agent;
    });

    console.log("Querying RC Analytics for Keys:", validKeys);

    // 3. Prepare RingCentral Analytics Request
    const { timeRange } = req.query;
    const timeFrom = new Date();
    // Subtract 1 hour to safely avoid "timeTo cannot be after current moment" error
    const timeTo = new Date(Date.now() - 3600000);

    console.log(`Preparing RC Request. Range: ${timeRange}, TimeFrom: ${timeFrom.toISOString()}, TimeTo: ${timeTo.toISOString()}`);

    if (timeRange === 'yesterday') {
      timeFrom.setUTCDate(timeFrom.getUTCDate() - 1);
      timeFrom.setUTCHours(0, 0, 0, 0);
      timeTo.setUTCDate(timeTo.getUTCDate() - 1);
      timeTo.setUTCHours(23, 59, 59, 999);
    } else if (timeRange === 'last7') {
      timeFrom.setUTCDate(timeFrom.getUTCDate() - 7);
      timeFrom.setUTCHours(0, 0, 0, 0);
    } else if (timeRange === 'last30') {
      timeFrom.setUTCDate(timeFrom.getUTCDate() - 30);
      timeFrom.setUTCHours(0, 0, 0, 0);
    } else {
      // Default to today
      timeFrom.setUTCHours(0, 0, 0, 0);
    }

    // Filter keys to ensure they are valid (numeric)
    const numericKeys = validKeys.filter(k => /^\d+$/.test(k));

    if (numericKeys.length === 0) {
      console.log("No valid numeric keys found for RingCentral analytics.");
      return res.json({ global: {}, agents: [] });
    }

    console.log("Querying RC Analytics for Keys:", numericKeys);

    const requestBody = {
      grouping: {
        groupBy: "Users",
        keys: numericKeys
      },
      timeSettings: {
        timeZone: "UTC",
        timeRange: {
          timeFrom: timeFrom.toISOString(),
          timeTo: timeTo.toISOString()
        }
      },
      responseOptions: {
        counters: {
          allCalls: { aggregationType: "Sum" }
        },
        timers: {
          allCallsDuration: { aggregationType: "Sum" }
        }
      }
    };

    // 4. Call RingCentral API
    let data;
    try {
      const apiResponse = await platform.post('/analytics/calls/v1/accounts/~/aggregation/fetch', requestBody);
      data = await apiResponse.json();
      console.log("RC Response Data:", JSON.stringify(data, null, 2));
    } catch (e) {
      console.error("Error fetching RingCentral stats:", e);
      if (e.response) {
        try {
          const errorBody = await e.response.json();
          console.error("RC Error Body:", JSON.stringify(errorBody, null, 2));
        } catch (jsonErr) {
          console.error("RC Error Body (text):", await e.response.text().catch(() => "Could not read body"));
        }
      }
      return res.status(500).json({ error: "Error al obtener estadísticas de RingCentral" });
    }


    // 5. Process Data
    const agentStats = [];
    let globalCalls = 0;
    let globalDuration = 0;

    // Map RC data back to our agents
    if (data.data && data.data.records) {
      for (const record of data.data.records) {
        // Use our map to find the agent
        const agent = keyToAgentMap[record.key];

        if (agent) {
          // Check for 'values' (which RC seems to return) or 'sum'
          const calls = record.counters?.allCalls?.values || record.counters?.allCalls?.sum || 0;
          // Timer key might be 'allCalls' or 'allCallsDuration' depending on API version/response
          const duration = record.timers?.allCalls?.values || record.timers?.allCallsDuration?.values || record.timers?.allCallsDuration?.sum || 0; // in seconds

          // Calculate metrics
          // User Rule: 8 hours work - 2 hours break = 6 hours effective work per day
          let days = 1;
          if (timeRange === 'last7') days = 7;
          if (timeRange === 'last30') days = 30;

          const effectiveHoursPerDay = 6;
          const totalEffectiveHours = days * effectiveHoursPerDay;

          const callsPerHour = totalEffectiveHours > 0 ? (calls / totalEffectiveHours).toFixed(2) : 0;

          // Time Between Calls: (Total Time - Talk Time) / Total Calls
          const totalTimeSeconds = totalEffectiveHours * 3600;
          const avgTimeBetweenCalls = calls > 0 ? ((totalTimeSeconds - duration) / calls).toFixed(0) : 0;

          agentStats.push({
            name: agent.username,
            calls,
            duration,
            callsPerHour,
            avgTimeBetweenCalls
          });

          globalCalls += calls;
          globalDuration += duration;
        }
      }
    }

    // Global Stats Calculation
    // Use the same 6-hour rule
    let days = 1;
    if (timeRange === 'last7') days = 7;
    if (timeRange === 'last30') days = 30;

    const effectiveHoursPerDay = 6;
    const totalEffectiveHoursGlobal = days * effectiveHoursPerDay; // Total hours per agent
    // Let's go with Average Agent Performance:
    const globalCallsPerHour = (agents.length > 0 && totalEffectiveHoursGlobal > 0)
      ? (globalCalls / (totalEffectiveHoursGlobal * agents.length)).toFixed(2)
      : 0;

    // Global Time Between Calls
    // Total Man-Hours available = Total Effective Hours * Agents
    const globalTotalTimeSeconds = totalEffectiveHoursGlobal * 3600 * agents.length;
    const globalAvgTimeBetweenCalls = globalCalls > 0 ? ((globalTotalTimeSeconds - globalDuration) / globalCalls).toFixed(0) : 0;

    res.json({
      global: {
        callsPerHour: globalCallsPerHour,
        avgTimeBetweenCalls: globalAvgTimeBetweenCalls
      },
      agents: agentStats
    });

  } catch (err) {
    console.error("Error fetching RingCentral stats:", err);
    res.status(500).json({ error: "Failed to fetch RingCentral stats" });
  }
});

// Iniciar servidor
httpServer.listen(PORT, () => {
  console.log(`🚀 DOV backend en http://localhost:${PORT}`);
  connectDB();
});

// Middleware de manejo de errores
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send("Algo salió mal!");
});
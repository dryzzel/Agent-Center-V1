import fs from "fs-extra";
import { MongoClient } from "mongodb";
import bcrypt from "bcryptjs";
import dotenv from "dotenv";

dotenv.config();

const MONGO_URI = process.env.MONGO_URI || "mongodb://localhost:27017";
const DB_NAME = "call-center";
const USERS_FILE = "./users.json";

async function migrateUsers() {
  let client;
  try {
    client = new MongoClient(MONGO_URI);
    await client.connect();
    const db = client.db(DB_NAME);
    const usersCollection = db.collection("users");

    console.log("Conectado a MongoDB para migración...");

    if (await fs.pathExists(USERS_FILE)) {
      const users = await fs.readJSON(USERS_FILE);
      
      // Eliminar usuarios existentes para evitar duplicados
      await usersCollection.deleteMany({});
      console.log("Colección de usuarios purgada.");

      // Insertar usuarios del archivo JSON
      await usersCollection.insertMany(users);
      console.log(`${users.length} usuarios migrados exitosamente.`);

    } else {
      // Si no existe el archivo, crear un admin por defecto
      const adminExists = await usersCollection.findOne({ username: "admin" });
      if (!adminExists) {
        const hashedPassword = await bcrypt.hash("admin123", 10);
        await usersCollection.insertOne({
          username: "admin",
          password: hashedPassword,
          email: "admin@dov.com",
          role: "admin",
          stats: {},
          lastActivity: new Date().toISOString(),
        });
        console.log("Usuario administrador por defecto creado.");
      }
    }
  } catch (err) {
    console.error("Error durante la migración:", err);
  } finally {
    if (client) {
      await client.close();
      console.log("Conexión con MongoDB cerrada.");
    }
  }
}

migrateUsers();

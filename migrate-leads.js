import { MongoClient } from "mongodb";
import dotenv from "dotenv";

dotenv.config();

const MONGO_URI = process.env.MONGO_URI || "mongodb://localhost:27017";
const DB_NAME = "call-center";

const leads = [
  {
    "Name": "John Doe",
    "Phone": "1234567890",
    "Address": "123 Main St",
    "Email or Second Phone": "john.doe@example.com",
    "Product": "Product A",
    "Prev. Status": "New",
    "Call Log": "",
    "DISPOSITION": null,
    "Timestamp": null,
    "notes": null,
    "callback": null,
    "assignedTo": null
  },
  {
    "Name": "Jane Smith",
    "Phone": "0987654321",
    "Address": "456 Oak Ave",
    "Email or Second Phone": "jane.smith@example.com",
    "Product": "Product B",
    "Prev. Status": "New",
    "Call Log": "",
    "DISPOSITION": null,
    "Timestamp": null,
    "notes": null,
    "callback": null,
    "assignedTo": null
  }
];

async function migrateLeads() {
  let client;
  try {
    client = new MongoClient(MONGO_URI);
    await client.connect();
    const db = client.db(DB_NAME);
    const leadsCollection = db.collection("leads");

    console.log("Conectado a MongoDB para migración de leads...");

    await leadsCollection.deleteMany({});
    console.log("Colección de leads purgada.");

    await leadsCollection.insertMany(leads);
    console.log(`${leads.length} leads migrados exitosamente.`);

  } catch (err) {
    console.error("Error durante la migración de leads:", err);
  } finally {
    if (client) {
      await client.close();
      console.log("Conexión con MongoDB cerrada.");
    }
  }
}

migrateLeads();

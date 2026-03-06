const mongoose = require("mongoose");

const connectDB = async () => {
  const mongoUri = process.env.MONGODB_URI || "mongodb://localhost:27017/ai-nids";
  try {
    const conn = await mongoose.connect(mongoUri);
    console.log(`[DB] MongoDB connected: ${conn.connection.host}`);
  } catch (err) {
    console.error(`[DB] Error: ${err.message}`);
    // Don't exit, continue without database
    console.log("[DB] Running without database - some features may not work");
  }
};

module.exports = connectDB;

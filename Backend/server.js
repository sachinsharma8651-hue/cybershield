const express = require("express");
const cors = require("cors");
const dotenv = require("dotenv");
const connectDB = require("./config/db");
const userRoutes = require("./routes/userRoutes");
const scanRoutes = require("./routes/scanRoutes");
dotenv.config();

connectDB();

const app = express();

app.use(cors({
    origin: "*",
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allowedHeaders: ["Content-Type", "Authorization"]
}));


app.use(express.json());



app.get("/", (req, res) => {
    res.send("🚀 CyberShield Backend is Running Successfully!");
});

app.use("/api/users", userRoutes);
app.use("/api/scan", scanRoutes);

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
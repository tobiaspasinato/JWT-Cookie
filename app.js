const express = require('express');
const app = express();

const dotenv = require('dotenv');
dotenv.config();

const authRoutes = require("./routes/auth.routes.js");
// const userRoutes = require("./routes/use.routes.js");

app.use(express.json());

app.use("/auth", authRoutes);

app.listen(process.env.PORT, () => {
    console.log(`Server is running on http://localhost:${process.env.PORT}`);
});
require("dotenv").config();

const express = require('express');
const cors = require('cors');
require('./config/dbConnection')

const app = express();

app.use(cors());

app.use((err, req, res, next) => {

    err.statusCode = err.statusCode || 500;
    err.message = err.message || "Internal Server Error";
    res.status(err.statusCode).json({
        message: err.message
    })

})


app.listen(3000, () => console.log('Server is running on port 3000'));
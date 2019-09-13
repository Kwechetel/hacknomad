require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const helmet = require('helmet')

const authRoutes = require('./routes/auth');

const app = express();

app.use(helmet());

app.use((req, res, next) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, PATCH, DELETE');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization')
    next();
});
///app.use(bodyParser.urlencoded({ extended: false }))
app.use(bodyParser.json());

app.use('/auth',authRoutes);


app.listen(process.env.PORT || 8080, () => {
    console.log('server started successfully');
})

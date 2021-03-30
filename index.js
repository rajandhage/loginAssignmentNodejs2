const express = require('express');
const app = express();
const mongoose = require('mongoose');
const dotenv = require('dotenv');
const cors = require("cors");
var morgan = require('morgan');
var fs = require('fs');
var path = require('path')

const authRoute = require('./routes/auth');
const postRoute = require('./routes/posts');
const settingsRoute = require('./routes/settings');

dotenv.config();

var corsOptions = {
    origin: "http://localhost:3000"
  };
  app.use(cors(corsOptions));

//connect to DB
mongoose.connect(process.env.DB_CONNECT, { useNewUrlParser: true, useUnifiedTopology: true } , ()=>console.log('Connnected to db!!'));

//Middleware
app.use(express.json());
app.use((req,res,next)=>{
  console.log('inside backend') 
  next()
})

//import routes
app.use('/api/user/', authRoute);
app.use('/api/user/settings', settingsRoute);
app.use('/api/posts', postRoute);

//page not found
app.get('/*', (req, res)=>{
    res.send('404 page not found');
  }
)

app.listen(process.env.BACKEND_PORT, () => console.log('server up and running'));
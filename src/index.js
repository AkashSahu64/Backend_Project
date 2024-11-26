// require('dotenv').config({path: './env'})
import dotenv from 'dotenv';
import connectDB from './db/index.js';

connectDB();

dotenv.config({
    path: './env'
})





/*
import mongoose from 'mongoose';
import {DB_NAME} from './constants';
import express from 'express';

const app = express();

(async() => { //ifie approch
    try{
        await mongoose.connect(`${process.env.MONGODB_URI}/${DB_NAME}`)
        app.on('error', (error) => {
            console.log('ERROR: ', error);
            throw err
        })

        app.listen(process.env.PORT, () =>{
            console.log(`App is serve ${process.env.PORT}`);
        })

    }catch(error){
        console.log('ERROR:', error);
        throw err
    }
})()*/
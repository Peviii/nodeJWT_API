const express = require('express')
const jwt = require('jsonwebtoken')
require('dotenv').config()

module.exports = (req, res, next) => {
    const { headers: { authorization } } = req;
    const token = authorization && authorization.split(" ")[1];
    if(!token){
        return res.status(401).json({ msg: "acesso negado" })
    }
    try{
        const secret = process.env.SECRET;
        jwt.verify(token, secret)
        next()
    }catch(error){
        return res.status(400).json({ msg: "token invalido" })
    }
}
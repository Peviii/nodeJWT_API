require('dotenv').config()
const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const User = require('./models/User')
require('./jwt/session')

//CONFIG
const app = express()
app.use(express.json())
//PRIVATE ROUTE
app.get('/user/:id', async (req, res) => {
    const id = req.params.id;
    const user = await User.findById(id, '-password');
    //middleware
    if(!user){
        return res.status(422).json({ msg: "usuario nao encontrado"})
    }
    res.status(200).json({ user })
});
// function session(req, res, next) {
//     const authHeaders = req.headers['authorization']
//     const token = authHeaders && authHeaders.split(" ")[1]
//     if(!token){
//         return res.status(401).json({ msg: "acesso negado" })
//     }
//     try{
//         const secret = process.env.SECRET;

//         jwt.verify(token, secret)
        
//         next()
//     }catch(error){
//         return res.status(400).json({ msg: "token invalido" })
//     }
// }
//MAIN ROUTE(PUBLIC)
app.get('/', (req, res) => {
    res.status(200).json({msg: 'bem vindo a API'})
});
//register route
app.post('/auth/register', async (req, res) => {
    const {name, email, password, confirmpassword} = req.body;
    if(!name) {return res.status(422).json({msg: 'nome obrigatorio'})}
    if(!email) {return res.status(422).json({msg: 'email obrigatorio'})}
    if(!password) {return res.status(422).json({msg: 'senha obrigatoria'})}
    if(password !== confirmpassword){
        return res.status(422).json({msg: 'as senhas não coincidem, devem ser iguais'})
    }
    //user existence checking
    const userExist = await User.findOne({ email: email })
    if(userExist){
        return res.status(422).json({msg: 'usuario ja existe, utilize outro email'})
    }
    //password crafting
    const salt = await bcrypt.genSalt(12)
    const hashing = await bcrypt.hash(password, salt)
    //create user
    const user = new User({
        name,
        email,
        password: hashing
    })
    try{
        await user.save()
        res.status(201).json({ msg: 'usuario criado com sucesso' })
    }catch(error){
        console.log(error)
        res.status(500).json({ msg: error })
    }
});
app.post('/auth/user', async (req, res) => {
    const { email, password } = req.body;
    //validation
    if(!email) return res.status(422).json({ msg: 'email obrigatorio' })
    if(!password) return res.status(422).json({ msg: 'senha obrigatoria' })
    const user = await User.findOne({ email: email })
    if(!user){
        return res.status(404).json({msg: 'usuario não encontrado'})
    }
    const passcheck = await bcrypt.compare(password, user.password)
    if(!passcheck){
        return res.status(422).json({ msg: "senha invalida" })
    }
    try{
        const secret = process.env.SECRET;
        const token = jwt.sign(
            {
                id: user._id,
            },
            secret
        )
        res.status(200).json({ msg: "usuario logado com sucesso", token})
    }catch(error){
        console.log(error)
        res.status(500).json({ msg: 'houve um erro no servidor, tente mais tarde'})
    }
});
//CONFIG
mongoose.connect(process.env.DB).then(() => {
    app.listen(3000, (req, res) => console.log("ON!"))
}).catch((error) => console.log(error))

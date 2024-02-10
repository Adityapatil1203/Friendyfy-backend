const authController = require("express").Router()
const User = require('../models/User')
const bcrypt = require("bcrypt")
const jwt = require("jsonwebtoken")


authController.post('/register',async (req,res) => {
    try {
        
        const isExisting = await User.findOne({email:req.body.email})

        if(isExisting){
            throw new Error("Email is alreay resisterd")
        }

        const hashedPassword = await bcrypt.hash(req.body.password , 10)

    const newUser = await User.create({...req.body,password:hashedPassword})

    const {password,...others} = newUser._doc //_doc (actual value of newuser )
    const token = jwt.sign({id:newUser._id},process.env.JWT_SECRET,{expiresIn:"365d"})
    

    return res.status(201).json({others,token})

    } catch (error) {
       
        return res.status(500).json(error.message)
       
    }
})


// Login
authController.post('/login',async (req,res)=>{
    try {

    //checking for email
     const user = await User.findOne({email:req.body.email})
     if(!user){
        throw new Error("Invalid credential");
     }

     // checking for password
     const comparePass = await bcrypt.compare(req.body.password,user.password)

     if(!comparePass){
        throw new Error("Invalid credential");
     }

     const {password,...others}  = user._doc
     const token = jwt.sign({id:user._id},process.env.JWT_SECRET,{expiresIn:"365d"})

   console.log("otheers login :",others);

     return res.status(200).json({others,token})
        
    } catch (error) {
        return res.status(500).json(error.message)
    }
})


module.exports = authController
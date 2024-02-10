const jwt = require("jsonwebtoken")

const verifyToken = (req,res,next)=>{
    if(!req.headers.authorization)return res.status(403).json({msg:"not authorized , No token"})

    if(req.headers.authorization){
       // const token = req.headers.authorization.split(" ")[1]
       const token = req.headers.authorization
        // data = {id: newUser._id}
        jwt.verify(token , process.env.JWT_SECRET, (err,data)=>{
       
            if(err)return res.status(403).json({msg:"wrong or expired token"})
            else {
                req.user = data// data = {id: newUser._id}
                next()
            }
        })
    }
}

module.exports = verifyToken
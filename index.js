const express = require("express")
const mongoose = require("mongoose")
const dotenv = require("dotenv").config()
const cors = require("cors")
const authController = require("./controllers/authController")
const userController = require("./controllers/userController")
const postController = require("./controllers/postController")
const commentController = require("./controllers/commentController")
const uploadController = require("./controllers/uploadController")
const PORT  = process.env.PORT || 5000
const app = express()


// mongoose.connect(process.env.MONGO_URL)
// .then(()=>{
//     console.log("database successfully connected")
// })
// .catch((err)=>{
//     console.log("error in connection ",err)
// })

//connnect database 
const connectToDatabase = async () => {
    try {
        await mongoose.connect(process.env.MONGO_URL, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
          
        });
        console.log("Database connected successfully");
        // Start the server after the database connection is established
       
    } catch (error) {
        console.error("Error connecting to the database:", error);
    }
};

connectToDatabase() ;
app.use(cors())
app.use(express.json())
app.use('/images',express.static('public/images'))
app.use(express.urlencoded({extended:true}))
app.use('/auth',authController)
app.use('/user',userController)
app.use('/post',postController)
app.use('/comment',commentController)
app.use('/upload',uploadController)

//connect backend app
app.get("/",(req,res)=>{
    res.send("hello")
})

app.listen(PORT,()=>{
    console.log(`server running on ${PORT}`)
})

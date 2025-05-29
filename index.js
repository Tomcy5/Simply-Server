const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const UserModel = require('./MODELS/Usermodel')
const PostModel = require('./models/PostModel')
const bcrypt = require('bcrypt')
const cookieParser = require('cookie-parser')
const jwt = require('jsonwebtoken')
const multer = require('multer');
const path = require('path');


const app = express()
app.use(express.json())
app.use(express.static('public'))
app.use(cors({
    origin : ["http://localhost:3000"],
    methods : ["GET","POST","PUT","DELETE"],
    credentials:true
}
))
app.use(cookieParser())

mongoose.connect('mongodb://127.0.0.1:27017/SIMPLYPOSTS')


// app.post('/login',(req,res)=>{
//     //console.log(req)
//     const {email,password} = req.body;
//     UserModel.findOne({email:email})
//         .then(user=>{
            
//             if(user){
//                 console.log(user.password)
//               const data=  bcrypt.compare(password,user.password)
           
//                     if(data){
//                         console.log(data)
//                         const token = jwt.sign({email:user.email, role:user.role},"secret-key",{expiresIn:"1d"})
//                         //res.cookie("token",token)
//                         return res.json({"token":token,Status:"login success"})
//                     }
//                     else{
//                         res.json({msg:"invalid password"})
//                     }
                
                                                                                                        
//             }
//             else{
//                 res.json("invalid user")

//             }
//         })
// })

app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await UserModel.findOne({ email: email });
    if (!user) {
      return res.json({ msg: "Invalid user" });
    }
    
    const isPasswordValid = await bcrypt.compare(password, user.password);
    if (!isPasswordValid) {
      return res.json({ msg: "Invalid password" });
    }
    
    const token = jwt.sign(
      { email: user.email, role: user.role },
      "secret-key",
      { expiresIn: "1d" }
    );

    // Set token as cookie, with secure settings
    res.cookie("token", token, {
      httpOnly: true,
      sameSite: "lax", // adjust if using HTTPS & cross-origin requests
      maxAge: 24 * 60 * 60 * 1000, // 1 day
    });

    return res.json({ Status: "login success", role: user.role });
    
  } catch (err) {
    console.error(err);
    res.status(500).json({ msg: "Internal server error" });
  }
});


app.post('/',(req,res)=>{
    const {name,email,password} = req.body;
    bcrypt.hash(password,10)
    .then(hash=>{
        UserModel.create({name,email,password:hash})
            .then(result=>res.json(result))
            .catch(err=>res.json(err))
    })
    .catch(err=>res.json(err))

})

const verifyuser = (req,res,next)=>{
    const token = req.cookies.token;
    // console.log(token);
    if(!token){
        return res.json("token is not available")
    }
    else{
        jwt.verify(token,"secret-key",(err,decoded)=>{
            if(err){
                return res.json("wrong token")
            }
            else{
                req.email = decoded.email;
                req.name = decoded.name;
                next()
                // if(decoded.role === 'admin'){
                //     next()
                // }
                // else{
                //     return res.json ("not admin")
                // }
            }
            
        })
    }
}
// app.get('/admin',verifyuser,(req,res)=>{
//     return res.json("log succ as admin")
// })


app.get('/home',verifyuser,(req,res)=>{
    res.json({email:req.email ,name:req.name})
    res.json('homepage okkk')

})

const storage = multer.diskStorage({
    destination : (req,file,callb)=>{
        callb(null,'Public/Images')
    },
    filename: (req,file,callb)=>{
        callb(null,file.fieldname + "_"+ Date.now() + path.extname(file.originalname))
    }
})

const upload = multer({
    storage: storage
})

app.post('/addpost',verifyuser,upload.single('file'),(req,res)=>{
    console.log(req.file);
    // const {title,description,file} =req.body;
PostModel.create({title:req.body.title,description:req.body.description,file:req.file.filename})
    .then(result => res.json("post added success"))
    .catch(err => res.json(err))
})

app.get('/getposts',(req,res)=>{
    PostModel.find()
        .then(posts => res.json(posts))
        .catch(err => res.json(err))
})


app.get('/viewpost/:id',(req,res)=>{
    const id = req.params.id;
    
 
    PostModel.findById({_id: id})
    .then(result=> res.json(result))

    .catch(err => console.log(err))
})

app.put('/editpost/:id',(req,res)=>{
    const id = req.params.id;
    // const {title,description}= req.body;
    PostModel.findByIdAndUpdate({_id: id}, {title: req.body.title, description: req.body.description})
    .then(result=> res.json("post updated"))

    .catch(err => console.log(err))
})

app.delete('/deletepost/:id',(req,res)=>{
    PostModel.findByIdAndDelete({_id: req.params.id})
    .then(result=> res.json("post deleted"))

    .catch(err => console.log(err))
})


app.get('/getalluserdata',(req,res)=>{
    UserModel.find()
        .then(result=> res.json(result) )

        .catch(err => res.json(err))
})

app.get('/logout',(req,res)=>{
    res.clearCookie('token')
    return res.json("cookie cleared")
})



app.listen(3001,()=>{
    console.log('running');
})
import mongoose from "mongoose";
import { Jwt } from "jsonwebtoken";
import {bcrypt} from "bcrypt"

const UserSchema = new mongoose.Schema(
    {
        userName :{
            type : String,
            required : true,
            unique : true,
            lowercase : true,
            trim : true,
            index : true
        },
        email :{
            type : String,
            required : true,
            unique : true,
            lowercase : true,
            trim : true
        },
        fullName :{
            type : String,
            required : true,
            trim : true,
            index : true
        },
        avatar :{
            type : String, //cloudinary url
            required : true
        },
        coverImage:{
            type : String, //cloudinary url
        },
        watchHistory:[
            {
                type : mongoose.Schema.Types.ObjectId,
                ref : "Video" 
            }
        ],
        password : {
            type : String,
            required : [true,'password is required']
        },
        refreshToken : {
            type : String
        }
    },{timestamps : true}
)

UserSchema.pre("save",async function(next){
    if(!this.isModified("password")) return next();
    this.password = bcrypt.hash(this.password, 10)
    next()
})

UserSchema.methods.isPasswordCorrect = async function(password){
    return await bcrypt.compare(password, this.password)
}

UserSchema.method.generateAccessToken = function(){
    return jwt.sign({
        _id : this._id,
        email : this.email,
        userName : this.userName,
        fullName : this.fullName
    }),
    process.env.ACCESS_TOKEN_SECRET,
    {
        expiresIn : process.env.ACCESS_TOKEN_EXPIRY
    }
}
UserSchema.method.generateRefreshToken = function(){
    return jwt.sign({
        _id : this._id,
        email : this.email,
        userName : this.userName,
        fullName : this.fullName
    }),
    process.env.REFRESH_TOKEN_SECRET,
    {
        expiresIn : process.env.REFRESH_TOKEN_EXPIRY
    }
}

export const User = mongoose.model("User",UserSchema)
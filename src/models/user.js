const mongoose = require('mongoose');
const validator = require('validator');
const bcryptjs = require('bcryptjs');
const jwt = require('jsonwebtoken');

const userSchema = mongoose.Schema({
    name: {
        type: String, 
        required: true,
        trim: true
    },
    email: {
        type: String,
        required: true, 
        unique:true,
        trim: true,
        lowercase: true,
        validate(value){
            if(!validator.isEmail(value)){
                throw new Error('Email is invalid');
            }
        }
    },
    password: {
        type: String,
        required: true,
        minlength: 7,
        trim: true,
        validate(value){
            if(value.toLowerCase().includes('password')){
                throw new Error('Password cannot contain "password"');
            }
        }
    },
    age: {
        type: Number,
        default: 0,
        validate(value){
            if(value < 0){
                throw new Error('Age must be a postive number');
            }
        }
    },
    tokens:[{
        token: {
            type: String,
            required:true
        }
    }]
});

/**
 * toJSON is a built in method
 * and here i override and implement this method
 * @returns {Array|Binary|*}
 */
userSchema.methods.toJSON = function(){
    const user = this;
    const userObject = user.toObject();

    delete userObject.password;
    delete userObject.tokens;

    return userObject;
}

/**
 * Each Schema can define instance and static methods for its model.
 * Methods is functions that belong to instance of Model
 */
userSchema.methods.generateAuthToken = async function() {
    const user = this;
    const token = jwt.sign({_id: user._id.toString()}, 'taskmanagerapi');

    user.tokens = user.tokens.concat({token: token});
    await user.save();

    return token;
}

/**
 * Each Schema can define instance and static methods for its model.
 * Statics are pretty much the same as methods but allow for defining 
 * functions that exist directly on your Model.
 */
userSchema.statics.findByCredentials = async (email, password) => {
    const user = await User.findOne({email: email});

    if(!user){
        throw new Error('Unable to login');
    }

    const isMatch = await bcryptjs.compare(password, user.password);

    if(!isMatch){
        throw new Error('Unable to login');
    }

    return user;
}

 /**
  * Match plain text password before saving
  * 
  *  pre  -> use before an event like validation or before saving 
  *  post -> use after an event such as after the user has been saved 
  */
 userSchema.pre('save', async function(next){
    const user = this;
    
    if(user.isModified('password')){
        user.password = await bcryptjs.hash(user.password, 8);
    }

    next();
 });

const User = mongoose.model('User', userSchema);

module.exports = User;


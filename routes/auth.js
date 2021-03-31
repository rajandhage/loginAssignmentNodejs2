const router = require('express').Router();
const User = require('../model/User');
const validation = require('../utils/validation');
const bcryptjs = require('bcryptjs');
const jwt = require('jsonwebtoken');
const verifyJWT = require('../utils/verifyJWT');
var passwordGenerator = require('generate-password');
var nodemailer = require("nodemailer");
const dotenv = require('dotenv');
const ip = require('ip');




//registration
router.post('/register', async (req, res)=>{
    //validation of req data
    const {error} = validation.registerValidation(req);
    if(error){
        return res.status(401).send(error.details[0].message);
    }
 
    //checking if same data exists

    const existingData = await User.findOne({email : req.body.email});
    if(existingData){
        if(existingData.isValidated === true)
            return res.status(402).send('User already exists');
        else{
            var user = existingData;
            
            //hashing the password
            const salt = await bcryptjs.genSalt(10);
            const hashedPassword = await bcryptjs.hash(req.body.password, salt);

            //change existing data with new one
            user.name = req.body.name;
            user.password = hashedPassword;
        }
    }else{
        //hashing the password
        const salt = await bcryptjs.genSalt(10);
        const hashedPassword = await bcryptjs.hash(req.body.password, salt);
    
        //create user
        var user = new User({
            name : req.body.name,
            email : req.body.email,
            password : hashedPassword,
        });
    }

    //save user
    try {
        var savedUser = await user.save();
    } catch (err) {
        res.status(400).send('Registration failed');
    }

    //generating validation link
    const verificationToken = jwt.sign({_id : savedUser._id}, process.env.TOKEN_SECRET, {expiresIn : process.env.REGISTRATION_TOKEN_EXPIRY_TIME})
    //we need to replace req.get('host') with address of deploying machine
    //const link = "http://"+req.get('host')+"/api/user/verifyEmail?verificationToken=" + verificationToken;
    const link = "http://" + ip.address() + ":" + process.env.BACKEND_PORT + "/api/user/verifyEmail?verificationToken=" + verificationToken;

    //sending verification email
    //configuring mail properties
    const smtpTransport = nodemailer.createTransport({
        service: process.env.MAIL_SERVICE,
        host: process.env.MAIL_SERVICE_HOST,
        requireTLS: true,
        port: process.env.MAIL_SERVICE_PORT,
        secure: false,
        auth: {
            user: process.env.MAIL_ACCOUNT_USER_ID,
            pass: process.env.MAIL_ACCOUNT_PASSWORD
        }
    });

    //mail options 
    const mailOptions = {
        from : 'company',
        to : req.body.email,
        subject : "email verification",
        text : "Hello user",
        html : "Hello user,<br> Please click on given link for email verification.<br><a href="+link+">Click here to verify</a><p>Thank you</p>"
    }

    try{
        let info = await smtpTransport.sendMail(mailOptions);
        res.send('please check for your mailbox (or spam) for verification email');
    }catch(err){
        res.status(400).send('Please try once again');
    }

    // res.send('Registeration completed successfully Now Sign-In');

});

//email verfication
router.get('/verifyEmail', verifyJWT.authEmailVerification , async (req, res) =>{
    const decoded = jwt.decode(req.query.verificationToken, {complete : true});
    const verified = jwt.verify(req.query.verificationToken, process.env.TOKEN_SECRET);
    // console.log(verified);
    const existingUser = await User.findOne({_id : verified._id});
    if(!existingUser){
        return res.status(400).send('Some problem with database');
    }
    //return res.send(existingUser)
    if(existingUser.isValidated === true){
        return res.send('Your email has already been validated.. no need to validate again!!');
    }
    existingUser.isValidated = true;

    try{
        const savedUser = existingUser.save();
        return res.send('Email validated. Registration Successful. Now you can login');
    }catch(err){
        return res.send('failed to validate. Please try again');
    }
    
})

//login
router.post('/login',async (req, res) => {
    //validation of data
    const {error} = validation.loginValidation(req);
    if(error){
        return res.status(400).send(error.details[0].message);
    }

    //checking if user exists
    const existingUser = await User.findOne({email : req.body.email});
    if(!existingUser){
        return res.status(403).send('emailId do not exists');
    }
    
    //checking password
    const validPass = await bcryptjs.compare(req.body.password, existingUser.password);
    if(!validPass){
        return res.status(404).send('password is wrong');
    }
    //checking if user is validated
    if(existingUser.isValidated === false){
        return res.status(403).send('emailId is not validated');
    }

    //create and assign token   
    //const token = jwt.sign({_id : existingUser._id}, process.env.TOKEN_SECRET, {expiresIn : process.env.TOKEN_EXPIRY_TIME});
    const token = generateAccessToken({_id : existingUser._id});
    //res.setHeader('accessToken', token);
    
    const refreshToken = jwt.sign({_id : existingUser._id}, process.env.REFRESH_TOKEN_SECRET);
    refreshTokens.push(refreshToken);
    //res.setHeader('refreshToken', refreshToken);

    //res.send('Logged in!!');
    res.header('accessToken', token).header('refreshToken', refreshToken).send('Logged in!!')
})

function generateAccessToken(tokenInputObject){
    return jwt.sign(tokenInputObject, process.env.TOKEN_SECRET, {expiresIn : process.env.TOKEN_EXPIRY_TIME});
}

//refershToken
let refreshTokens = [];

router.post('/refreshToken', async (req, res) => {
    const refreshToken = req.body.refreshToken;
    if(!refreshToken) return res.status(401).send('no refresh token present in request');
    if(!refreshTokens.includes(refreshToken)) return res.status(403).send('no such refresh token found in db');

    jwt.verify(refreshToken, process.env.REFRESH_TOKEN_SECRET, (err, user)=>{
        if(err) return res.send(403).send('wrong refresh token');
        const accessToken = generateAccessToken({_id : user._id});
        return res.send(accessToken);
    })
})

//logout
router.delete('/logout', (req, res) => {
    refreshTokens = refreshTokens.filter(token => token !== req.body.refreshToken);
    //console.log(refreshTokens);
    res.send('Logged Out!!');
    
})


router.post('/forgotPassword', async (req, res) => {
    //validate email format
    const {error} = validation.forgotPasswordValidation(req);
    if(error){
        return res.status(400).send(error.details[0].message);
    }
    //console.log(req.get('host'))

    //check for existing user
    const existingUser = await User.findOne({email : req.body.email});
    if(!existingUser){
        return res.status(400).send('No account exists for this email Id');
    }

    //generate temporary password
    const tempPassword = await passwordGenerator.generate({
        length: 10,
        numbers: true
    });

    //hashing the password
    const salt = await bcryptjs.genSalt(10);
    const hashedPassword = await bcryptjs.hash(tempPassword, salt);

    //updating existing user
    existingUser.password = hashedPassword;

    //saving updated user
    try {
        const savedUser = await existingUser.save();
    } catch (err) {
        return res.status(400).send('password generation failed. Please try again after some time');
    }
    
    const smtpTransport = nodemailer.createTransport({
        service: process.env.MAIL_SERVICE,
        host: process.env.MAIL_SERVICE_HOST,
        requireTLS: true,
        port: process.env.MAIL_SERVICE_PORT,
        secure: false,
        auth: {
            user: process.env.MAIL_ACCOUNT_USER_ID,
            pass: process.env.MAIL_ACCOUNT_PASSWORD
        }
    });

    //mail options 
    const mailOptions = {
        from : 'company',
        to : req.body.email,
        subject : "Temporary password",
        text : "Hello user",
        html : "Hello user,<br> This is your temporary password.<br><p>" + tempPassword + "</p><p>please login and reset your password</p>"
    }

    // let info = smtpTransport.sendMail(mailOptions, (error, response) => {
    //     if(error){
    //         return res.send(error);
    //     }
    //     // res.send(response);
    //     res.send('Mail has been sent to your email id. Please check your mailbox. Check in spam box if mail is not recieved');
    // })
    
    try{
        let info = await smtpTransport.sendMail(mailOptions);
        res.send('Mail has been sent to your email id. Please check your mailbox. Check in spam box if mail is not recieved');
    }catch(err){
        res.status(400).send('Please try once again');
    }
    
})

//page not found
router.get('/*',  (req, res)=>{
    res.send('404 page not found');
  }
)

module.exports = router;
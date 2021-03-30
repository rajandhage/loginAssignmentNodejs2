const router = require('express').Router();
const validation = require('../utils/validation');
const { auth } = require('../utils/verifyJWT');
const User = require('../model/User');
const bcryptjs = require('bcryptjs');


//reset password
router.post('/resetPassword', auth , async (req, res) => {
    const {error} = validation.resetPasswordValidation(req);
    if(error){
        return res.status(401).send(error.details[0].message);
    }

    const currentPassword = req.body.currentPassword;
    const newPassword = req.body.newPassword;
    const confirmNewPassword = req.body.confirmNewPassword;
    const userEmail = req.body.email;

    //retrieving data of existing user
    existingUser = await User.findOne({email : userEmail});

    //current password verification
    const validPass = await bcryptjs.compare(req.body.currentPassword, existingUser.password);
    if(!validPass){
        return res.status(404).send('current password is wrong');
    }

    //check password conditions
    if(newPassword === currentPassword){
        return res.status(404).send('New password can not be same as old password');
    }
    if(newPassword !== confirmNewPassword){
        return res.status(404).send('put same password in fields "new password" and "confirm new password"'); 
    }

    //hash new password
    const sugar = await bcryptjs.genSalt(10);
    existingUser.password = await bcryptjs.hash(newPassword, sugar);
    
    //update password
    try {
        const savedUser = existingUser.save();
    } catch (error) {
        return res.status(400).send('password updating has failed');
    }

    res.send('Password updated successfully');
})


//page not found
router.get('/*', (req, res)=>{
    res.send('404 page not found');
  }
)


module.exports = router;
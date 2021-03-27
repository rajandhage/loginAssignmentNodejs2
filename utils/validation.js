const Joi = require('joi');

const registerValidation = (req) => {
    const schema = Joi.object({
        name : Joi.string().min(3).required(),
        email : Joi.string().min(6).required().email(),
        password : Joi.string().min(6).required()
    });

    return schema.validate({name : req.body.name, email : req.body.email, password : req.body.password});
}

const loginValidation = (req) => {
    const schema = Joi.object({
        
        email : Joi.string().min(6).required().email(),
        password : Joi.string().min(6).required()
    });

    return schema.validate({email : req.body.email, password : req.body.password});
}

const forgotPasswordValidation = (req) => {
    const schema = Joi.object({
        email : Joi.string().min(6).required().email()
    })

    return schema.validate({email : req.body.email});
}

const resetPasswordValidation = (req) => {
    const schema = Joi.object({
        email : Joi.string().min(6).required().email(),
        currentPassword : Joi.string().min(6).required(),
        newPassword : Joi.string().min(6).required(),
        confirmNewPassword : Joi.string().min(6).required()
    })

    return schema.validate({email : req.body.email, currentPassword : req.body.currentPassword, newPassword : req.body.newPassword, confirmNewPassword : req.body.confirmNewPassword});
}
module.exports.registerValidation = registerValidation;
module.exports.loginValidation = loginValidation;
module.exports.forgotPasswordValidation = forgotPasswordValidation;
module.exports.resetPasswordValidation = resetPasswordValidation;
const router = require('express').Router();
const verifyJWT = require('../utils/verifyJWT');
const ip = require('ip');

router.get('/', verifyJWT.auth, (req, res) => {
    res.json({
        posts : {
            myipaddress : ip.address(),
            title : 'First post',
            description : 'first post description'
        }
    });
});

module.exports = router;
const router = require('express').Router();
const verify = require('./verifyToken');

router.get('/', verify, (req, res) => {
    res.json({
        posts: {
            title: 'my post',
            description: 'no access'
        }
    })
})



module.exports = router;
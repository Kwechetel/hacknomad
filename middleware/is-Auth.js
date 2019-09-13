const jwt = require('jsonwebtoken');

module.exports = (req, res, next) => {
    const authHeader = req.get('Authorization');
    if(!authHeader){

        res.status(401).json({status: 'Not authenticated.'})
        
        return false;
    }

    const auth = authHeader.split(' ')[1];

    let decodedToken;

    try{
        decodedToken = jwt.verify(auth, process.env.JW_SECRETE);
    }catch(err) {
        //err.statusCode = 400;
        //throw err;

        if(err) {
            res.json([{message: "Token expired"}])

            return false;
        }
    }

    if(!decodedToken) {
        res.status(4001).json([{auth: 'Not athenticated'}])

        return false;
    }
    console.log({auth: decodedToken});
    req.userId = decodedToken.id;
    next();
}
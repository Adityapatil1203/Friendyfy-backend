const jwt = require("jsonwebtoken")

const verifyToken = (req,res,next)=>{
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return res.status(403).json({ msg: "Not authorized. No token provided." });
    }

    // Extract the token from the Authorization header
    const token = authHeader
    if (!token) {
        return res.status(403).json({ msg: "Not authorized. Token format is invalid." });
    }

    // Verify the token
    jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
        if (err) {
            return res.status(403).json({ msg: "Invalid token or token has expired." });
        } else {
            // Attach the decoded user data to the request object
            console.log("decode ",decoded);
            req.user = decoded;
            console.log("req user ",req.user);
            next(); // Call next middleware or route handler
        }
    });
}

module.exports = verifyToken

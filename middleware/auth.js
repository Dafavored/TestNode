const jwt = require("jsonwebtoken");

module.exports = (req, res, next) => {
    const authHeader = req.headers.authorization;

    // Log the Authorization header
    console.log("Authorization Header:", authHeader);

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        console.error("Authorization header missing or malformed.");
        req.user = null;
        return next();
    }

    const token = authHeader.split(" ")[1];

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        console.log("Decoded token:", decoded); // Log decoded token for debugging
        req.user = decoded; // Attach decoded user info (id, role) to req
        next();
    } catch (err) {
        console.error("Token verification failed:", err.message);
        req.user = null; // Set user to null if token is invalid
        return res.status(401).json({ message: "Invalid or expired token" });
    }
};

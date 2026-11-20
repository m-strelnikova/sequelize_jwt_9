import jwt from "jsonwebtoken";
import User from "../models/User";

const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_key";

export async function authenticate(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).json({ success: false, message: "Unauthorized." });
    }

    const token = authHeader.split(" ")[1];

    try {
        const payload = jwt.verify(token, JWT_SECRET);
        const user = await User.findByPk(payload.userId);

        if (!user) {
            return res.status(401).json({ success: false, message: "User not found." });
        }

        req.user = user;
        next();
    } catch (error) {
        return res.status(401).json({ success: false, message: "Invalid token." });
    }
}

export function checkMustChangePassword(req, res, next) {
    if (req.user && req.user.mustChangePassword) {
        return res.status(403).json({
            success: false,
            redirectTo: "/change-password",
            message: "You must change your password before continuing.",
        });
    }
    next();
}

export function requireAdmin(req, res, next) {
    if (!req.user || req.user.role !== "admin") {
        return res.status(403).json({ success: false, message: "Access denied. Admins only." });
    }
    next();
}
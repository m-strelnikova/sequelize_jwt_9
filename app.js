import express from "express";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import "dotenv/config";
import sequelize from "./config/db.js";
import User from "./models/User.js";
import {
  authenticate,
  checkMustChangePassword,
  requireAdmin,
} from "./middleware/auth.js";

const app = express();
const port = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_key";

app.use(express.json());

app.post("/register", async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ success: false, message: "Email and password are required." });
  }

  try {
    const existingUser = await User.findOne({ where: { email } });
    if (existingUser) {
      return res.status(409).json({ success: false, message: "Email is already registered." });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = await User.create({
      email,
      password: hashedPassword,
      mustChangePassword: false,
      role: "user",
    });

    const token = jwt.sign({ userId: newUser.id, role: newUser.role }, JWT_SECRET, {
      expiresIn: "1d",
    });

    res.status(201).json({
      success: true,
      message: "User registered successfully.",
      token,
    });
  } catch (error) {
    console.error("Error in POST /register:", error);
    res.status(500).json({ success: false, message: "Registration failed." });
  }
});

app.post("/change-password", authenticate, async (req, res) => {
  const { newPassword } = req.body;

  if (!newPassword) {
    return res.status(400).json({ success: false, message: "New password is required." });
  }

  try {
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    await User.update(
      {
        password: hashedPassword,
        mustChangePassword: false,
      },
      {
        where: { id: req.user.id },
      }
    );

    res.status(200).json({ success: true, message: "Password updated successfully." });
  } catch (error) {
    console.error("Error in POST /change-password:", error);
    res.status(500).json({ success: false, message: "Failed to change password." });
  }
});

app.post("/delete-account", authenticate, checkMustChangePassword, async (req, res) => {
  const { password } = req.body;

  if (!password) {
    return res.status(400).json({ success: false, message: "Current password is required." });
  }

  try {
    const isMatch = await bcrypt.compare(password, req.user.password);
    if (!isMatch) {
      return res.status(401).json({ success: false, message: "Invalid password." });
    }

    await User.destroy({
      where: { id: req.user.id },
    });

    res.status(200).json({ success: true, message: "Account deleted successfully." });
  } catch (error) {
    console.error("Error in POST /delete-account:", error);
    res.status(500).json({ success: false, message: "Failed to delete account." });
  }
});

app.get("/admin", authenticate, checkMustChangePassword, requireAdmin, async (req, res) => {
  res.status(200).json({
    success: true,
    message: "Welcome to the admin panel.",
  });
});

app.post("/change-email", authenticate, checkMustChangePassword, async (req, res) => {
  const { newEmail, password } = req.body;

  if (!newEmail || !password) {
    return res.status(400).json({ success: false, message: "New email and current password are required." });
  }

  try {
    const isMatch = await bcrypt.compare(password, req.user.password);
    if (!isMatch) {
      return res.status(401).json({ success: false, message: "Invalid password." });
    }

    const existingUser = await User.findOne({ where: { email: newEmail } });
    if (existingUser && existingUser.id !== req.user.id) {
      return res.status(409).json({ success: false, message: "Email is already in use." });
    }

    await User.update(
      { email: newEmail },
      { where: { id: req.user.id } }
    );

    res.status(200).json({ success: true, message: "Email updated successfully." });
  } catch (error) {
    console.error("Error in POST /change-email:", error);
    res.status(500).json({ success: false, message: "Failed to change email." });
  }
});

app.listen(port, async () => {
  try {
    await sequelize.authenticate();
    console.log("Connection to the database has been established");
    console.log(`Server is running on http://localhost:${port}`);
  } catch (error) {
    console.error("Enable to connect to the database: ", error);
  }
});
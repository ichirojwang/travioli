/**
 * authentication routes
 * /api/auth/<route>
 */

import express from "express";
import { getMe, login, logout, pingPong, signup } from "../controllers/auth.controller.js";
import authenticateToken from "../middleware/authenticateToken.js";
import validateData from "../middleware/validateData.js";
import { loginSchema, signupSchema } from "../schemas/auth.schemas.js";

const router = express.Router();

router.get("/ping", pingPong);
router.post("/signup", validateData(signupSchema), signup);
router.post("/login", validateData(loginSchema), login);
router.post("/logout", logout);
router.get("/me", authenticateToken, getMe);

/**
 * Possible features
 *
 * change password
 * verify email
 * reset password
 */

export default router;

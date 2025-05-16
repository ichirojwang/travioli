import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import prisma from "../db/prisma.js";
import internalServerError from "../utils/internalServerError.js";
import { DecodedToken } from "../types/global.js";
import { REFRESH_COOKIE_NAME } from "../utils/generateToken.js";

const authenticateToken = async (
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const token = req.cookies[REFRESH_COOKIE_NAME];

    // check if token was given
    if (!token) {
      res.status(401).json({ message: "Unauthorized - No token provided" });
      return;
    }

    const secret = process.env.ACCESS_TOKEN_SECRET;
    if (!secret) {
      throw new Error("Missing JWT secret environment variable");
    }

    // check if token is valid
    const decoded = jwt.verify(token, process.env.JWT_SECRET!) as DecodedToken;
    if (!decoded) {
      res.status(401).json({ message: "Unauthorized - Invalid token" });
      return;
    }

    // find user and select useful fields
    const user = await prisma.user.findFirst({
      where: { id: decoded.userId, isDeleted: false },
    });

    if (!user) {
      res.status(404).json({ message: "User not found" });
      return;
    }

    // add user and tokenType to Request
    req.user = user;
    req.tokenType = decoded.tokenType;

    next();
  } catch (error: unknown) {
    internalServerError("authenticateToken middleware", error, res);
  }
};

export default authenticateToken;

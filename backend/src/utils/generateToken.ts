import jwt from "jsonwebtoken";
import { Response } from "express";
import { DecodedToken, TokenType } from "../types/global.js";

// access token short-lived 15m, refresh token long 7d
const ACCESS_TOKEN_EXPIRY = "15m";
const REFRESH_TOKEN_EXPIRY = "7d";
export const REFRESH_COOKIE_NAME = "jwt";

/**
 * generate a JWT token
 * @param userId to include in the payload
 * @param isRefreshToken for checking whether JWT token was generated via a refresh token or thru authenticating user credentials. used for flagging sensitive operations
 * @param res Response object from controller
 * @returns JWT token
 */
const generateToken = (userId: string, tokenType: TokenType, res: Response): string => {
  const payload: DecodedToken = { userId, tokenType };

  const secret =
    tokenType === "access" ? process.env.ACCESS_TOKEN_SECRET : process.env.REFRESH_TOKEN_SECRET;
  if (!secret) {
    throw new Error("Missing JWT secret environment variable");
  }

  const token = jwt.sign(payload, secret, {
    expiresIn: tokenType === "access" ? ACCESS_TOKEN_EXPIRY : REFRESH_TOKEN_EXPIRY,
  });

  if (tokenType === "refresh") {
    res.cookie(REFRESH_COOKIE_NAME, token, {
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days represented as milliseconds
      httpOnly: true,
      sameSite: "strict",
      secure: process.env.NODE_ENV !== "development",
    });
  }

  return token;
};

export default generateToken;

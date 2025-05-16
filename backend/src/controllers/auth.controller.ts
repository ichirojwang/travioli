import { CookieOptions, Request, Response } from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import prisma from "../db/prisma.js";
import generateToken, { REFRESH_COOKIE_NAME } from "../utils/generateToken.js";
import internalServerError from "../utils/internalServerError.js";
import sanitizeUser from "../utils/sanitizeUser.js";
import { LoginBody, SignupBody } from "../schemas/auth.schemas.js";
import { DecodedToken } from "../types/global.js";

/**
 * method simply for testing backend connection
 */
export const pingPong = (req: Request, res: Response): void => {
  res.status(200).json({ message: "pong" });
  return;
};

/**
 * - signup
 * - request body should include: email, username, password, confirmPassword
 */
export const signup = async (req: Request<{}, {}, SignupBody>, res: Response): Promise<void> => {
  try {
    // ensure data is validated first. check validateData middleware
    const { email, username, password } = req.body;

    // parallel check for if email and username are unique
    const [emailExists, usernameExists] = await Promise.all([
      prisma.user.findUnique({ where: { email } }),
      prisma.user.findUnique({ where: { username } }),
    ]);

    if (emailExists) {
      res.status(400).json({ message: `Account with the email ${email} already exists` });
      return;
    }
    if (usernameExists) {
      res.status(400).json({ message: `Account with the username ${username} already exists` });
      return;
    }

    // hashing the password to store in database
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // creating new user with hashed password. throws error if fail
    const newUser = await prisma.user.create({
      data: {
        email,
        username,
        password: hashedPassword,
      },
    });

    // after validating user, generate both access and refresh token
    generateToken(newUser.id, "access", res);
    generateToken(newUser.id, "refresh", res);

    // return user with sanitized data as a json object with created status
    const filteredUser = sanitizeUser(newUser);
    res.status(201).json({ user: filteredUser });
  } catch (error: unknown) {
    internalServerError("signup controller", error, res);
  }
};

/**
 * - login
 * - request body should include: email, password
 */
export const login = async (req: Request<{}, {}, LoginBody>, res: Response): Promise<void> => {
  try {
    // ensure data is validated first. check validateData middleware
    const { email, password } = req.body;

    // look for a matching user
    const user = await prisma.user.findFirst({ where: { email, isDeleted: false } });

    // no user found
    if (!user) {
      res.status(400).json({ message: "User not found" });
      return;
    }

    // make sure password is correct
    const isPasswordCorrect = await bcrypt.compare(password, user.password);
    if (!isPasswordCorrect) {
      res.status(400).json({ message: "Invalid credentials" });
      return;
    }

    // after validating user, generate both access and refresh token
    generateToken(user.id, "access", res);
    generateToken(user.id, "refresh", res);

    // return user with sanitized data
    const filteredUser = sanitizeUser(user);
    res.status(200).json({ user: filteredUser });
  } catch (error: unknown) {
    internalServerError("login controller", error, res);
  }
};

/**
 * - logout
 */
export const logout = async (req: Request, res: Response): Promise<void> => {
  try {
    // clearing jwt cookie
    const options: CookieOptions = {
      httpOnly: true,
      sameSite: "strict",
      secure: process.env.NODE_ENV !== "development",
    };
    res.clearCookie(REFRESH_COOKIE_NAME, options);

    res.status(204).json({ message: "Logged out successfully" });
  } catch (error: unknown) {
    internalServerError("logout controller", error, res);
  }
};

/**
 * - this method is for checking if a user is logged in
 */
export const getMe = async (req: Request, res: Response): Promise<void> => {
  try {
    const user = req.user;

    // if user is not logged in
    if (!user) {
      res.status(401).json({ message: "User not authorized. Please log in" });
      return;
    }

    // return user with sanitized data
    const filteredUser = sanitizeUser(user);
    res.status(200).json({ user: filteredUser });
  } catch (error: unknown) {
    internalServerError("getMe controller", error, res);
  }
};

export const refreshToken = async (req: Request, res: Response): Promise<void> => {
  try {
    const token = req.cookies[REFRESH_COOKIE_NAME];
    if (!token) {
      res.status(401).json({ message: "Unauthorized - No refresh token" });
      return;
    }

    const secret = process.env.REFRESH_TOKEN_SECRET;
    if (!secret) {
      throw new Error("Missing JWT secret environment variable");
    }

    const decoded = jwt.verify(token, secret) as DecodedToken;
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

    const accessToken = generateToken(decoded.userId, "access", res);

    res.status(200).json({ accessToken });
  } catch (error: unknown) {
    internalServerError("refreshToken controller", error, res);
  }
};

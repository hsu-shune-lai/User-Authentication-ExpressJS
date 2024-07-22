import { NextFunction, Request, Response } from "express";
import jwt from "jsonwebtoken";

export const checkAuth = (req: Request, res: Response, next: NextFunction) => {
  const token = req.cookies.token;

  if (!token) {
    return res.status(401).redirect("/signin.html");
  }

  jwt.verify(token, "7DM3l91T0W4x5tLEVwuF", (err) => {
    if (err) {
      return res.status(401).send("Unauthorized");
    }

    next();
  });
};
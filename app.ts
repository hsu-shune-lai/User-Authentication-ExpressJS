import bcrypt from "bcryptjs";
import bodyParser from "body-parser";
import express, { Request, Response } from "express";
import fs from "fs";
import jwt from "jsonwebtoken";
import cookieParse from "cookie-parser";
import { checkAuth } from "./auth";

const PORT = 5000;
const app = express();

app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParse());

// Load user data from users.json (create the file if it doesn't exist)
let users: { email: string; password: string }[] = [];
try {
  const userData = fs.readFileSync("./data/users.json", "utf-8");
  users = JSON.parse(userData);
} catch (error) {
  users = [];
}

app.post("/signup", (req: Request, res: Response) => {
  const { email, password } = req.body;

  // Validation
  if (!email || !password) {
    return res.status(400).send("Email and password are required");
  }

  // Hash the password using bcryptjs
  const salt = bcrypt.genSaltSync(10);
  const hash = bcrypt.hashSync(password, salt);

  const newUser = { email, password: hash };
  users.push(newUser);

  // Save the updated user list to users.json
  fs.writeFileSync("./data/users.json", JSON.stringify(users, null, 2));

  res.status(201).send("User registered successfully");
});

app.post("/signin", (req: Request, res: Response) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).send("Email and password are required");
  }

  const user = users.find((user) => user.email === email);

  if (!user) {
    return res.status(401).send("User not found");
  }

  const passwordMatch = bcrypt.compareSync(password, user.password);

  if (!passwordMatch) {
    return res.status(401).send("Invalid credentials");
  }

  app.post("/logout", (req: Request, res: Response) => {
    res.clearCookie("token"); // Clear the token cookie
    res.redirect("/signin.html"); // Redirect to the sign-in page after logout
  });

  //Create and send a JWT token upon successful authentication
  const token = jwt.sign({ email }, "7DM3l91T0W4x5tLEVwuF", {
    expiresIn: "1h",
  });
  console.log(token);
  res.cookie("token", token);
  res.redirect("/");
});

// Proxy
app.get("/data", checkAuth, (req: Request, res: Response) => {
  res.sendFile(__dirname + "/data/app-data.json");
});

app.get("/", checkAuth, (req: Request, res: Response) => {
  res.sendFile(__dirname + "/index.html");
});

app.listen(PORT, () => console.log(`Server has started listening on ${PORT}`));

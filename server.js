// NodeJS server backend via nodemon and ExpressJS framework
const express = require('express');
const database = require("better-sqlite3")("database.sql") // create database
database.pragma("jounal_mode = WAL") // optimize database

const app = express();
app.use(express.urlencoded({ extended: false })) // access POST values
app.use(express.static("public"))


app.get("/", (req, res) => {
    app.render("login.html");
});

app.get("/register", (req, res) => {
    app.render("register.html");
});

app.get("/home", (req, res) => {
    app.render("home.html");
});

app.get("/post", (req, res) => {
    app.render("post.html");
});

app.listen(3030);
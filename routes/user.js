const express = require("express");
const connection = require("../connection");
const router = express.Router();

const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");

require("dotenv").config();

var auth = require("../services/authentication");
var checkRole = require("../services/checkRole");

router.post("/signup", (request, response) => {
  let user = request.body;
  query = 'select email, password, role, status from user where email=?';

  connection.query(query, [user.email], (error, results) => {
    // Querying database checking to see if an email on the user table currently exists
    if (!error) {
      //this if statement check if the connection to the database is successful or not

      if (results.length <= 0) {
        // checks if the email exists by returning any emails that matches input and comparing their length
        query =
          'insert into user(name, contactNumber, email, password, status, role) values(?, ?, ?, ?, "false", "user")';
        connection.query(
          query,
          [user.name, user.contactNumber, user.email, user.password],
          (error, results) => {
            if (!error) {
              return response
                .status(201)
                .json({ message: "Successfully Registered" });
            } else return response.status(500).json(error);
          }
        );
      } else
        return response.status(400).json({ message: "Email Already Exists" });
    } else return response.status(500).json(error);
  });
});

router.post("/login", (request, response) => {
  const user = request.body;
  query = 'select email, password, role, status from user where email=?';
  connection.query(query, [user.email], (error, results) => {
    if (!error) {
      if (results.length <= 0 || results[0].password != user.password) {
        return response
          .status(401)
          .json({ message: "Incorrect Email or Password" });
      } else if (results[0].status === "false") {
        return response
          .status(401)
          .json({ message: "Wait for Admin approval" });
      } else if (results[0].password == user.password) {
        const details = { email: results[0].email, role: results[0].role };
        const accessToken = jwt.sign(details, process.env.ACCESS_TOKEN, {
          expiresIn: "8hr",
        });
        response.status(200).json({ token: accessToken });
      } else
        return response
          .status(400)
          .json({ message: "Something went wrong. Please try again later" });
    } else return response.status(500).json(error);
  });
});

var transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL,
    pass: process.env.PASSWORD,
  },
});

router.post("/forgotpassword", (request, response) => {
  const user = request.body;
  query = 'select email, password from user where email=?';
  connection.query(query, [user.email], (error, results) => {
    if (!error) {
      if (results.length <= 0) {
        return response
          .status(200)
          .json({ message: "Password successfully sent to your email." });
      } else {
        var mailOptions = {
          from: process.env.EMAIL,
          to: results[0].email,
          subject: "Password by Cafe Management System",
          html:
            "<p><b>Your Login details for --------- system</b><br><b>Email:</b>" +
            results[0].email +
            "<br><b>Password: </b> " +
            results[0].password +
            '<br><a href="localhost:4200/">Click here to login</a></p>',
        };
        transporter.sendMail(mailOptions, function (error, info) {
          if (error) {
            console.log(error);
          } else console.log("Email sent:", info.response);
        });
        return response
          .status(200)
          .json({ message: "Password sent successfully to your email." });
      }
    }
  });
});

router.get(
  "/get",
  auth.authenticateToken,
  checkRole.checkRole,
  (request, response) => {
    var query =
      'select id, name, email, password, contactNumber, status from user where role = "user"';
    //be sure to remove password from query
    connection.query(query, (error, results) => {
      if (!error) {
        return response.status(200).json(results);
      } else return response.status(200).json(error);
    });
  }
);

router.patch(
  "/update",
  auth.authenticateToken,
  checkRole.checkRole,
  (request, response) => {
    let user = request.body;
    var query = 'update user set status=? where id=?';
    connection.query(query, [user.status, user.id], (error, results) => {
      if (!error) {
        if (results.affectedRows == 0) {
          return response
            .status(401)
            .json({ message: "User id does not exist" });
        } else
          return response
            .status(200)
            .json({ message: "User Updated Successfully" });
      } else return response.status(500).json(error);
    });
  }
);

router.get(
  "/checkToken",
  auth.authenticateToken,
  checkRole.checkRole,
  (request, response) => {
    return response.status(200).json({ message: "true" });
  }
);
//I do not understand the change password endpoint it does not make sense tbh
router.post("/changePassword", auth.authenticateToken, (request, response) => {
  const user = request.body;
  const email = response.locals.email;
  var query = 'select *from user where email=? and password=?';
  connection.query(query, [email, user.oldPassword], (error, results) => {
    if (!error) {
      if (results.length <= 0) {
        return response.status(400).json({ message: "Incorrect Old Password" });
      } else if (results[0].password === user.oldPassword) {
        query = "update user set password=? where email=?";
        connection.query(query, [user.newPassword, email], (error, results) => {
          if (!error) {
            return response.status(200).json({ message: "Password Updated" });
          } else return response.status(500).json(error);
        });
      } else {
        return response
          .status(500)
          .json({ message: "Something went wrong please try again later" });
      }
    } else return response.status(500).json(error);
  });
});

module.exports = router;

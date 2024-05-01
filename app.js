const express = require("express");
const cors = require("cors");
const { createPool } = require("mysql");
const app = express();
app.use(cors());
app.use(express.json());
const jwt = require("jsonwebtoken");
const forge = require("node-forge");
const bodyParser = require("body-parser");
const crypto = require("crypto");

const JWT_SECRET = "jedikey";
const con = createPool({
  host: "cerdatabase.cnue620m87uo.ap-southeast-2.rds.amazonaws.com",
  user: "admin",
  password: "admin123",
  database: "cerdatabase",
  port: "3306",
  multipleStatements: true,
});

// INITIAL
app.get("/", (req, res) => {
  console.log("hello");
  con.query("select * from cer", (e, r, f) => {
    if (e) {
      return console.log(e);
    }
    result = r;
    return console.log(r);
  });
  res.status(200).send("HELLO");
});

// LOGIN
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  con.query(
    "SELECT * FROM user WHERE username = ?",
    [username],
    (error, results) => {
      if (error) {
        console.error("Database error:", error);
        return res.status(500).send("Error during database query");
      }

      if (results.length === 0) {
        return res.status(401).send("No user found with the given ID");
      }

      const user = results[0];

      if (user.password !== password) {
        return res.status(401).send("Password does not match");
      }
      console.log({ id: user.id, username: user.username });

      const token = jwt.sign(
        { id: user.id, username: user.username, state: user.state },
        JWT_SECRET,
        {
          expiresIn: "2h",
        }
      );

      res.status(200).send({ token: token });
    }
  );
});

function authenticateToken(req, res, next) {
  // Retrieve the token from the request headers
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1]; // Bearer TOKEN

  if (token == null) return res.sendStatus(401); // if no token is found, return 401

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403); // if token is not valid, return 403
    req.user = user; // Add the user payload to the request
    next(); // Proceed to the next middleware function
  });
}

// certificate
app.post("/generate-certificate", (req, res) => {
  try {
    const csrPem = req.body.csrPem;
    if (!csrPem) {
      return res.status(400).send({ error: "No CSR provided" });
    }

    // Function to create a certificate from CSR
    const certificatePem = createCertificateFromCSR(csrPem);
    res.send({ certificate: certificatePem });
  } catch (error) {
    console.error("Error processing the CSR:", error);
    res.status(500).send({ error: "Failed to process the CSR" });
  }
});

function createCertificateFromCSR(csrPem) {
  const csr = forge.pki.certificationRequestFromPem(csrPem);
  if (!csr.verify()) {
    throw new Error("Invalid CSR");
  }
  const keys = forge.pki.rsa.generateKeyPair(512);

  let cert = forge.pki.createCertificate();
  cert.serialNumber = forge.util.bytesToHex(forge.random.getBytesSync(16));
  cert.validity.notBefore = new Date();
  cert.validity.notAfter = new Date();
  cert.validity.notAfter.setFullYear(cert.validity.notBefore.getFullYear() + 1);
  cert.publicKey = keys.publicKey;
  cert.setSubject([
    {
      shortName: "CN",
      value: "PeaceKeeper",
    },
    {
      shortName: "O",
      value: "BanchangPki",
    },
    {
      shortName: "OU",
      value: "Secure Division", // Optional: Remove if not needed
    },
  ]);
  cert.setIssuer(csr.subject.attributes);

  // Simulate CA's private key (use CA's private key in production)

  cert.sign(keys.privateKey);
  console.log("generate certificate success");

  return forge.pki.certificateToPem(cert);
}

app.get("/key/:id", authenticateToken, (req, res) => {
  const userId = req.params.id;
  const query = "SELECT publicKey, privateKey FROM user WHERE id = ?";

  con.query(query, [userId], (err, results) => {
    if (err) {
      console.error("Error retrieving data:", err);
      return res.status(500).send("Failed to retrieve data");
    }

    if (results.length > 0) {
      const user = results[0];
      res.json({
        publicKey: user.publicKey,
        privateKey: user.privateKey,
      });
    } else {
      res.status(404).send("User not found");
    }
  });
});

// REVOKE
app.post("/revoke/:id/:state", (req, res) => {
  const { id, state } = req.params;
  const certDetails = req.body;
  console.log(
    `Received certificate details for user ID ${id} in state ${state}:`,
    certDetails
  );

  const tableName = getTableName(state);
  if (!tableName) {
    res.status(400).send("Invalid state provided");
    return;
  }

  insertCertDetails(certDetails, id, tableName, res);
});

function getTableName(state) {
  switch (state) {
    case "northern":
      return "northernCrl";
    case "southern":
      return "southernCrl";
    case "northeaster":
      return "northeasterCrl";
    case "central":
      return "centralCrl";
    default:
      return null;
  }
}

function insertCertDetails(details, userId, tableName, res) {
  const { serialNumber, issuer, validFrom, validTo, issuedBy, publicKey } =
    details;
  con.query(
    `INSERT INTO ${tableName} (user_id, serialNumber, issuer, validFrom, validTo, issuedBy, publicKey) VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [userId, serialNumber, issuer, validFrom, validTo, issuedBy, publicKey],
    (err, results) => {
      if (err) {
        console.error("Failed to insert certificate details:", err);
        res.status(500).send("Failed to store certificate details");
      } else {
        console.log("Inserted certificate details with ID:", results.insertId);
        res.status(200).send("Certificate details received successfully");
      }
    }
  );
}

// GET REVOKE
app.get("/getrevoke/:id/:state", (req, res) => {
  const { id, state } = req.params;
  const tableName = getTableName(state);

  if (!tableName) {
    res.status(400).send("Invalid state provided");
    return;
  }

  getRevokeDetails(id, tableName, res);
});

function getRevokeDetails(userId, tableName, res) {
  con.query(
    `SELECT * FROM ${tableName} WHERE user_id = ?`,
    [userId],
    (err, results) => {
      if (err) {
        console.error("Failed to retrieve certificate details:", err);
        res.status(500).send("Failed to retrieve data");
      } else if (results.length > 0) {
        res.status(200).json(results);
      } else {
        res
          .status(404)
          .send("No certificate details found for the given user ID and state");
      }
    }
  );
}
// Start the server
const port = process.env.PORT || 8000;
app.listen(port, () => {
  console.log(`Server is running on port ${port}`);
});

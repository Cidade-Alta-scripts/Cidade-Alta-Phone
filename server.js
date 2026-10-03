const express = require("express");
const crypto = require("crypto");
const path = require("path");
const { Pool } = require("pg");

const app = express();
const PORT = process.env.PORT || 3000;

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL
    ? { rejectUnauthorized: false }
    : false
});

app.use(express.json({ limit: "3mb" }));
app.use(express.static(path.join(__dirname, "public")));

const sessions = new Map();

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY,
      name TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS ads (
      id SERIAL PRIMARY KEY,
      seller_id INTEGER NOT NULL REFERENCES users(id),
      title TEXT NOT NULL,
      price NUMERIC NOT NULL,
      category TEXT NOT NULL,
      description TEXT DEFAULT '',
      image TEXT DEFAULT '',
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS messages (
      id SERIAL PRIMARY KEY,
      sender_id INTEGER NOT NULL REFERENCES users(id),
      receiver_id INTEGER NOT NULL REFERENCES users(id),
      text TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);

  console.log("Banco Cidade Alta conectado.");
}

function hash(password) {
  return crypto
    .createHash("sha256")
    .update(password)
    .digest("hex");
}

function createToken() {
  return crypto.randomBytes(32).toString("hex");
}

async function generateID() {
  while (true) {
    const id = Math.floor(1000 + Math.random() * 9000);

    const result = await pool.query(
      "SELECT id FROM users WHERE id = $1",
      [id]
    );

    if (result.rows.length === 0) {
      return id;
    }
  }
}

async function auth(req, res, next) {
  const token = (req.headers.authorization || "")
    .replace("Bearer ", "");

  const userID = sessions.get(token);

  if (!userID) {
    return res.status(401).json({
      error: "Você precisa estar logado."
    });
  }

  const result = await pool.query(
    "SELECT id, name FROM users WHERE id = $1",
    [userID]
  );

  if (!result.rows[0]) {
    return res.status(401).json({
      error: "Usuário não encontrado."
    });
  }

  req.user = result.rows[0];
  next();
}

/* CADASTRO */

app.post("/api/register", async (req, res) => {
  try {
    const name = String(req.body.name || "").trim();
    const password = String(req.body.password || "");

    if (!name || password.length < 4) {
      return res.status(400).json({
        error: "Digite um nome e uma senha de pelo menos 4 caracteres."
      });
    }

    const id = await generateID();

    await pool.query(
      `INSERT INTO users
       (id, name, password_hash)
       VALUES ($1, $2, $3)`,
      [id, name, hash(password)]
    );

    const token = createToken();

    sessions.set(token, id);

    res.json({
      token,
      user: {
        id,
        name
      }
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Erro ao criar conta."
    });
  }
});

/* LOGIN */

app.post("/api/login", async (req, res) => {
  try {
    const id = Number(req.body.id);
    const password = String(req.body.password || "");

    const result = await pool.query(
      `SELECT id, name, password_hash
       FROM users
       WHERE id = $1`,
      [id]
    );

    const user = result.rows[0];

    if (!user || user.password_hash !== hash(password)) {
      return res.status(401).json({
        error: "ID ou senha incorretos."
      });
    }

    const token = createToken();

    sessions.set(token, user.id);

    res.json({
      token,
      user: {
        id: user.id,
        name: user.name
      }
    });
  } catch (error) {
    res.status(500).json({
      error: "Erro ao entrar."
    });
  }
});

/* SAIR */

app.post("/api/logout", auth, (req, res) => {
  const token = (req.headers.authorization || "")
    .replace("Bearer ", "");

  sessions.delete(token);

  res.json({
    success: true
  });
});

/* USUÁRIO */

app.get("/api/me", auth, (req, res) => {
  res.json(req.user);
});

/* OLX */

app.get("/api/ads", async (req, res) => {
  try {
    const q = `%${String(req.query.q || "").trim()}%`;

    const result = await pool.query(
      `SELECT
        ads.id,
        ads.title,
        ads.price,
        ads.category,
        ads.description,
        ads.image,
        ads.created_at,
        users.id AS seller_id,
        users.name AS seller_name
       FROM ads
       JOIN users ON users.id = ads.seller_id
       WHERE
         ads.title ILIKE $1
         OR ads.category ILIKE $1
         OR users.name ILIKE $1
       ORDER BY ads.id DESC`,
      [q]
    );

    res.json(result.rows);
  } catch (error) {
    res.status(500).json({
      error: "Erro ao carregar anúncios."
    });
  }
});

app.post("/api/ads", auth, async (req, res) => {
  try {
    const title = String(req.body.title || "").trim();
    const price = Number(req.body.price);
    const category = String(req.body.category || "").trim();
    const description = String(req.body.description || "").trim();
    const image = String(req.body.image || "").trim();

    if (!title || !price || !category) {
      return res.status(400).json({
        error: "Preencha título, preço e categoria."
      });
    }

    const result = await pool.query(
      `INSERT INTO ads
       (seller_id, title, price, category, description, image)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING *`,
      [
        req.user.id,
        title,
        price,
        category,
        description,
        image
      ]
    );

    res.json({
      ...result.rows[0],
      seller_id: req.user.id,
      seller_name: req.user.name
    });
  } catch (error) {
    console.error(error);

    res.status(500).json({
      error: "Erro ao publicar anúncio."
    });
  }
});

/* CHAT */

app.get("/api/messages/:id", auth, async (req, res) => {
  try {
    const otherID = Number(req.params.id);

    const result = await pool.query(
      `SELECT *
       FROM messages
       WHERE
         (sender_id = $1 AND receiver_id = $2)
         OR
         (sender_id = $2 AND receiver_id = $1)
       ORDER BY id ASC`,
      [req.user.id, otherID]
    );

    res.json(result.rows);
  } catch (error) {
    res.status(500).json({
      error: "Erro ao carregar conversa."
    });
  }
});

app.post("/api/messages/:id", auth, async (req, res) => {
  try {
    const receiverID = Number(req.params.id);
    const text = String(req.body.text || "").trim();

    if (!text) {
      return res.status(400).json({
        error: "Mensagem vazia."
      });
    }

    const receiver = await pool.query(
      "SELECT id FROM users WHERE id = $1",
      [receiverID]
    );

    if (!receiver.rows[0]) {
      return res.status(404).json({
        error: "Usuário não encontrado."
      });
    }

    const result = await pool.query(
      `INSERT INTO messages
       (sender_id, receiver_id, text)
       VALUES ($1, $2, $3)
       RETURNING *`,
      [
        req.user.id,
        receiverID,
        text
      ]
    );

    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({
      error: "Erro ao enviar mensagem."
    });
  }
});

/* SITE */

app.get("*", (req, res) => {
  res.sendFile(
    path.join(__dirname, "public", "index.html")
  );
});

initDatabase()
  .then(() => {
    app.listen(PORT, "0.0.0.0", () => {
      console.log(
        `Cidade Alta Phone rodando na porta ${PORT}`
      );
    });
  })
  .catch(error => {
    console.error("Erro no banco:", error);
    process.exit(1);
  });
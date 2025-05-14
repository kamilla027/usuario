const express = require('express');
const mysql = require('mysql2');
const bcrypt = require('bcrypt');
const session = require('express-session');
const bodyParser = require('body-parser');
const path = require('path');

const app = express();
const PORT = 3000;

// Conexão com o MySQL (XAMPP)
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'quiz' // Troque se seu banco tiver outro nome
});

db.connect((err) => {
  if (err) {
    console.error('Erro ao conectar no MySQL:', err);
  } else {
    console.log('✅ Conectado ao MySQL!');
  }
});

// Configurações
app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'views')));
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
  secret: 'segredo123',
  resave: false,
  saveUninitialized: false
}));

// Middleware: proteger rotas
function proteger(req, res, next) {
  if (req.session.usuario) {
    next();
  } else {
    res.redirect('/login');
  }
}

// ROTAS HTML
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.get('/cadastro', (req, res) => {
  res.sendFile(path.join(__dirname, 'views/cadastro.html'));
});

app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'views/login.html'));
});

app.get('/usuario', proteger, (req, res) => {
  res.sendFile(path.join(__dirname, 'views/usuario.html'));
});

// API: dados do usuário logado
app.get('/api/usuario', proteger, (req, res) => {
  const email = req.session.usuario;
  db.query('SELECT nome, email FROM usuarios WHERE email = ?', [email], (err, results) => {
    if (err) return res.status(500).send('Erro no banco');
    res.json(results[0]);
  });
});

// POST: cadastro
// POST: cadastro (com alerta simples para e-mail duplicado)
app.post('/cadastro', async (req, res) => {
  const { nome, email, senha } = req.body;
  const senhaCripto = await bcrypt.hash(senha, 10);

  db.query('INSERT INTO usuarios (nome, email, senha) VALUES (?, ?, ?)',
    [nome, email, senhaCripto],
    (err) => {
      if (err && err.code === 'ER_DUP_ENTRY') {
        // E-mail já cadastrado
        return res.send(`
          <script>
            alert("Este e-mail já está sendo usado!");
            window.location.href = "/cadastro";
          </script>
        `);
      } else if (err) {
        // Outro erro qualquer
        console.error(err);
        return res.status(500).send('Erro ao cadastrar');
      }
      // Cadastro feito com sucesso
      res.redirect('/login');
    });
});


// POST: login (com alertas)
app.post('/login', (req, res) => {
  const { email, senha } = req.body;

  db.query('SELECT * FROM usuarios WHERE email = ?', [email], async (err, results) => {
    if (err) return res.status(500).send('Erro interno');

    if (results.length === 0) {
      return res.send(`
        <script>
          alert("Usuário não encontrado!");
          window.location.href = "/login";
        </script>
      `);
    }

    const usuario = results[0];
    const senhaOk = await bcrypt.compare(senha, usuario.senha);

    if (senhaOk) {
      req.session.usuario = usuario.email;
      res.redirect('/usuario');
    } else {
      res.send(`
        <script>
          alert("Senha incorreta!");
          window.location.href = "/login";
        </script>
      `);
    }
  });
});

// LOGOUT
app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login');
  });
});

// Iniciar servidor
app.listen(PORT, () => {
  console.log(`🚀 Servidor rodando em http://localhost:${PORT}`);
});

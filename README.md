# auth-documentation

## 1. Estrutura de Pastas Sugerida

```text
src/
├── controllers/ # Trata requisições e respostas HTTP
├── services/    # Regras de negócio e lógica de banco de dados
├── routes/      # Definição dos endpoints e middlewares
├── middlewares/ # Validação de JWT e checagem de Roles
└── utils/       # Funções de criptografia (hash/compare)

```

## 2. Camada de Segurança (Utils)

```javascript
const bcrypt = require('bcrypt');
const SALT_ROUNDS = 10;

const hashPassword = async (password) => await bcrypt.hash(password, SALT_ROUNDS);
const comparePassword = async (password, hash) => await bcrypt.compare(password, hash);

module.exports = { hashPassword, comparePassword };

```

## 3. Camada de Negócio (Services)

```javascript
const jwt = require('jsonwebtoken');
const { hashPassword, comparePassword } = require('../utils/security');
// Supondo um model de banco de dados
const User = require('../models/User');

class AuthService {
  async register(email, password, role = 'user') {
    const hashed = await hashPassword(password);
    return await User.create({ email, password: hashed, role });
  }

  async login(email, password) {
    const user = await User.findOne({ email });
    if (!user) throw new Error('Credenciais inválidas');

    const isValid = await comparePassword(password, user.password);
    if (!isValid) throw new Error('Credenciais inválidas');

    const token = jwt.sign(
      { id: user.id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '8h' }
    );

    return { token, user: { id: user.id, email: user.email, role: user.role } };
  }
}

module.exports = new AuthService();

```

## 4. Camada de Controle (Controllers)

```javascript
const AuthService = require('../services/authService');

const login = async (req, res) => {
  try {
    const { email, password } = req.body;
    const data = await AuthService.login(email, password);
    return res.json(data);
  } catch (error) {
    return res.status(401).json({ error: error.message });
  }
};

module.exports = { login };

```

## 5. Autorização e Roles (Middlewares)

### Validação de Token (Authentication)

```javascript
const jwt = require('jsonwebtoken');

const protect = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ msg: 'Não autorizado' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded; // Injeta os dados do token (id, role) na requisição
    next();
  } catch (err) {
    return res.status(403).json({ msg: 'Token inválido' });
  }
};

```

### Validação de Cargos (Authorization/RBAC)

```javascript
const authorize = (...allowedRoles) => {
  return (req, res, next) => {
    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ msg: 'Acesso negado: privilégios insuficientes' });
    }
    next();
  };
};

```


## 6. Definição de Rotas

```javascript
const express = require('express');
const router = express.Router();
const { login } = require('../controllers/authController');
const { protect, authorize } = require('../middlewares/auth');

// Rota Pública
router.post('/login', login);

// Rota Protegida (Qualquer logado)
router.get('/meu-perfil', protect, (req, res) => res.send(req.user));

// Rota Administrativa (Apenas admin)
router.delete('/usuario/:id', protect, authorize('admin'), (req, res) => {
  res.send('Usuário deletado');
});

// Rota de Editor ou Admin
router.post('/post', protect, authorize('admin', 'editor'), (req, res) => {
  res.send('Post criado');
});

module.exports = router;

```

## 7. Resumo de Segurança

1. **Armazenamento**: Jamais salve a senha pura. Use sempre `bcrypt` com salt.
2. **Transporte**: Use sempre HTTPS para que o Token no header não seja interceptado.
3. **Payload**: Não coloque dados sensíveis (senhas, documentos) dentro do JWT, pois ele pode ser lido por qualquer um (é apenas Base64).
4. **Roles**: Valide as permissões sempre no **Backend**. O Frontend apenas esconde botões, o Backend é quem realmente bloqueia a ação.

Este modelo de consulta está pronto para ser aplicado no seu **NestJS** (adaptando para Decorators) ou em um projeto **Express** puro. Gostaria que eu detalhasse como implementar a **Revogação de Tokens** (Blacklist) caso um usuário faça logout ou mude de senha?

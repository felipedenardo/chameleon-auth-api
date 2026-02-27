# 🦎 Chameleon Auth API

O **Chameleon Auth API** é o microsserviço de **Identidade e Gerenciamento de Acesso (IAM)** central do Ecossistema Chameleon Agent AI. Ele atua como um Provedor de Identidade (IdP) e Servidor de Autenticação Única (SSO), sendo o único componente responsável pelo armazenamento seguro de credenciais, gestão de perfis e emissão de tokens de acesso (JWT).

O serviço utiliza a biblioteca [chameleon-common](https://github.com/felipedenardo/chameleon-common) para garantir padronização em logs, respostas HTTP e validações em todo o ecossistema.

---

## 🚀 Tecnologias e Arquitetura

Este projeto foi desenvolvido com foco em performance, segurança e manutenibilidade:

- **Linguagem:** Go 1.24.3
- **API Framework:** [Gin Gonic](https://github.com/gin-gonic/gin)
- **ORM:** [GORM](https://gorm.io/) com PostgreSQL
- **Cache & Sessão:** [Redis](https://redis.io/) (Blacklist de tokens e controle de versão)
- **Documentação:** [Swagger/OpenAPI](https://github.com/swaggo/swag)
- **Segurança Infra:** Docker Non-Root execution (usuário dedicado)
- **Arquitetura:** Baseada em **Hexagonal / Clean Architecture**, com Strongly Typed Domain (Types/Constants), Graceful Shutdown e Error Mapping de infraestrutura para domínio.

---

## ✨ Funcionalidades Principais

- [x] **Registro de Usuários:** Cadastro público com papel padrão `user`.
- [x] **Autenticação JWT:** Emissão de `access` e `refresh` tokens com expiração configurável.
- [x] **Gestão de Sessão (Token Versioning):** Capacidade de invalidar todas as sessões de um usuário instantaneamente (ex: após troca de senha ou banimento).
- [x] **Segurança Avançada:**
    - Blacklist de tokens no Logout.
    - Hash de senhas usando `bcrypt`.
    - Soft Delete para usuários desativados.
- [x] **Validação de Senhas:** Mínimo de 8 caracteres com maiúscula, minúscula e especial.
- [x] **Rate Limit:** Proteção contra abuso em login, refresh e recuperação de senha.
- [x] **Recuperação de Senha:** Fluxo completo de "Esqueci minha senha" com tokens de reset.
- [x] **Controle Administrativo:** Endpoint para alteração de status de usuários (Ativo, Inativo).
- [x] **Resiliência e Ciclo de Vida:**
    - Suporte a **Graceful Shutdown** (SIGINT/SIGTERM).
    - Fechamento limpo de conexões Postgres e Redis.

---

## 🛠️ Configuração e Execução

### Pré-requisitos
- [Docker](https://docs.docker.com/get-docker/) e [Docker Compose](https://docs.docker.com/compose/install/).
- [Go 1.24+](https://golang.org/doc/install) (para execução local sem Docker).

### Execução com Docker (Recomendado)
```bash
docker-compose up -d
```

### Execução Local
1. Instale as dependências:
   ```bash
   go mod tidy
   ```
2. Execute a aplicação:
   ```bash
   go run cmd/api/main.go
   ```

---

## 📖 API Reference

A documentação interativa (Swagger) está disponível em:
`http://localhost:8081/chameleon-auth/swagger/index.html`

### Endpoints Principais

| Método | Endpoint | Protegido | Descrição |
| :--- | :--- | :---: | :--- |
| `POST` | `/api/v1/auth/register` | ❌ | Cadastro de novo usuário |
| `POST` | `/api/v1/auth/login` | ❌ | Autenticação e obtenção de token |
| `POST` | `/api/v1/auth/refresh` | ❌ | Renovação de tokens |
| `POST` | `/api/v1/auth/logout` | ✅ | Encerramento de sessão (Blacklist + revogação do refresh) |
| `POST` | `/api/v1/auth/logout-all` | ✅ | Encerramento de todas as sessões (token_version) |
| `POST` | `/api/v1/auth/change-password` | ✅ | Alteração de senha do usuário logado |
| `POST` | `/api/v1/auth/forgot-password` | ❌ | Solicitação de reset de senha |
| `POST` | `/api/v1/auth/reset-password` | ❌ | Finalização do reset de senha |
| `POST` | `/api/v1/auth/deactivate` | ✅ | Desativação da própria conta |
| `PUT` | `/api/v1/admin/users/:id/status`| ✅ | (Admin) Alterar status de usuário |

### Variáveis de Ambiente Relevantes

```
JWT_SECRET=coloque-uma-chave-segura-com-32-caracteres-ou-mais
JWT_ISSUER=chameleon-auth-api
JWT_AUDIENCE=chameleon-services

TOKEN_TTL_HOURS=24
REFRESH_TOKEN_TTL_DAYS=30
RESET_TOKEN_TTL_MINUTES=30

MAX_BODY_BYTES=1048576

LOGIN_RATE_LIMIT=10
LOGIN_RATE_WINDOW_SEC=60
REFRESH_RATE_LIMIT=30
REFRESH_RATE_WINDOW_SEC=60
FORGOT_RATE_LIMIT=5
FORGOT_RATE_WINDOW_SEC=300
```

---

## 🏗️ Estrutura do Projeto

```text
.
├── cmd/api/             # Ponto de entrada da aplicação
├── internal/
│   ├── api/             # Handlers HTTP e DTOs
│   ├── app/             # Injeção de dependência e rotas
│   ├── domain/          # Entidades e Regras de Negócio (Interfaces)
│   ├── infra/           # Repositórios (Postgres/Redis) e Migrations
│   └── config/          # Carregamento de variáveis de ambiente
├── docs/                # Arquivos gerados pelo Swagger
└── api-specs/           # Especificações da API
```

# Fornecedor Produto V11 — acesso com login e senha

Aplicativo de importação de XML NF-e, GTIN (cEAN), GTIN tributável/DUN14 (cEANTrib), código de referência, descrição, unidade e fator de embalagem.

## Hospedagem

Este projeto **não funciona no GitHub Pages**, pois precisa de Node.js e PostgreSQL para autenticação de usuários. Faça deploy no Railway com este repositório, configure DATABASE_URL, NODE_ENV=production, ADMIN_EMAIL e ADMIN_PASSWORD (mínimo 12 caracteres), e use npm start. Configure PGSSLMODE=require somente se o seu banco exigir SSL. O administrador inicial é criado no primeiro início, e pode cadastrar outros usuários em /admin.

## Privacidade dos dados

A base original do HTML usa armazenamento local do navegador (localStorage e IndexedDB). A autenticação restringe o acesso pela aplicação hospedada, mas **os dados XML não são sincronizados, nem segregados por usuário no mesmo navegador**. Perfis distintos do navegador são recomendados até implementar armazenamento multiusuário no servidor. Nunca coloque credenciais no repositório.

## Testes locais

Node 20+, PostgreSQL, npm install, ajuste variáveis do .env.example no ambiente, npm run check e npm start.

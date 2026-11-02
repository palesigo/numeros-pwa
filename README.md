# Os meus números (PWA)

PWA offline para guardar números de identificação (CC, NIF, Segurança Social, Utente SNS, seguros, outros) por pessoa, com data de validade opcional.

App: https://palesigo.github.io/numeros-pwa/

- Sem servidor: os dados ficam no `localStorage`, cifrados com AES-GCM (chave derivada por PBKDF2 da palavra-passe mestra).
- Sem recuperação de palavra-passe. Exporta backups regularmente (botão ⬇️).
- Sem dependências nem build.

## Testar localmente
    python -m http.server 8080
Abrir http://localhost:8080

## Publicar no GitHub Pages
Settings → Pages → Deploy from branch → `main` / `/ (root)`.

## Atualizar a app
Ao alterar ficheiros, incrementar `CACHE` em `sw.js` (ex.: `numeros-v2`).

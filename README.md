# BOOYAH MARKET — Firestore backend

1. Firebase Console → Project settings → Service accounts → **Generate new private key**.
2. `cp .env.example .env` and fill in `FIREBASE_SERVICE_ACCOUNT` (or `FIREBASE_SERVICE_ACCOUNT_FILE`) and `ADMIN_PASSWORD`.
3. Firebase Console → Firestore → Rules → paste `firestore.rules` (blocks all direct client access).
4. `npm install && npm start` → open http://localhost:3000

The server also serves `public/` (your 4 HTML pages), so `API_BASE=''` just works.
If the page is hosted elsewhere or inside the Android WebView, set `API_BASE` in `public/index.html`
and `public/delete-account.html` to your server URL (e.g. `https://your-app.onrender.com`).
Never put the service-account key or admin password in the HTML.

## Netlify
1. Push this folder to GitHub (the .gitignore keeps keys out) and "Import project" in Netlify.
2. Netlify > Site settings > Environment variables, add:
   FIREBASE_PROJECT_ID, FIREBASE_CLIENT_EMAIL, FIREBASE_PRIVATE_KEY (from your service-account json), ADMIN_PASSWORD
3. Deploy. `/api/*` is routed to the function by netlify.toml, so API_BASE stays ''.

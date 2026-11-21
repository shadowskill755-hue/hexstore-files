# Hex Store upgrade

## New
- Hex Coins: everyone gets 300 free on first login (existing accounts get it the next time they open the app). Wallet page with balance and history.
- Paid apps: the upload form has a Price section: Free / Hex Coins / Real cash transfer.
- Cash keys: admin makes keys in Moderation. Developers enter a key and account details to unlock real-cash selling. Buyers pay the developer directly; the developer confirms in Wallet and the app unlocks.
- Shop: 13 upgrades per app page, with live preview and color/speed customisation.
- Paid APK files are locked on the server, not just hidden in the UI.

## Speed
- Smaller app lists, 20s edge cache for signed-out visitors, missing DB indexes added, parallel queries on app pages,
  cached GitHub release lookup on upload, light notification polling (paused when tab hidden), instant paint from cache,
  hover/touch prefetch, lazy images, faster service worker, resumable downloads.

## Database
Upgrade is automatic on first request after deploy. migrations/001_hex_coins.sql is for reference only.


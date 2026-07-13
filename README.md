# WP-Plugins

## application-passwords/
Adds **Settings → Application Passwords** (generate / revoke) for sites without
the core feature. Install: upload `application-passwords.zip` via **Plugins →
Add New → Upload Plugin**, or copy the folder to `wp-content/plugins/`.
REST + HTTPS only. Reads passwords from a prior version, so upgrading never
requires regenerating.

### Automatic updates (GitHub Releases)
1. Put this folder in a **public** GitHub repo (code has no secrets).
2. In `application-passwords.php` set `APW_GH_REPO` to `owner/repo`.
3. To ship an update:
   - bump `Version:` in the plugin header,
   - commit, then create a **GitHub Release** tagged `vX.Y.Z`,
   - attach the built `application-passwords.zip` as a **release asset**.
4. Every site checks the repo (~every 6h) and, on WP 5.5+, updates in the
   background automatically; older WP shows a one-click update.

Notes: keep the release tag (`v1.2.0`) matching the header `Version` (1.2.0).
The `Update URI` header stops the defunct wp.org "application-passwords" plugin
from hijacking updates by slug. Private repos would need auth on both the API
and the asset download — use a public repo.

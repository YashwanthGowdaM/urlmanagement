# MyURLs
Personal link dashboard. Go (stdlib) + one embedded HTML file.

Run locally: `ADMIN_PASSWORD=secret DATA_FILE=./urls.json go run .` then open http://localhost:8080
(the session cookie is `Secure`, so use localhost or HTTPS).

Deploy: set repo secrets SSH_PRIVATE_KEY, SSH_HOST, SSH_USER, ADMIN_PASSWORD and point the
`myurls.yashwanthgowdam.in` A record at the VM (ports 80/443 open). Push to main.

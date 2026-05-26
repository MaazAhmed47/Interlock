"""Local Supabase Auth redirect shim.

Supabase Auth may send development magic links to http://localhost:3000 when the
project Site URL is still the default. The access token is in the URL fragment,
so a normal HTTP redirect cannot see it. This tiny page uses browser JavaScript
to preserve the fragment and move it to the Interlock dashboard callback route.
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TARGET = "http://localhost:4173/dashboard/auth/callback"

HTML = f"""<!doctype html>
<html lang=\"en\">
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>Interlock Auth Redirect</title>
  <style>
    body {{ margin:0; min-height:100vh; display:grid; place-items:center; background:#060608; color:#f5f0e8; font-family:Inter,system-ui,sans-serif; }}
    main {{ width:min(560px, calc(100vw - 32px)); border:1px solid rgba(0,229,200,.22); background:rgba(245,240,232,.04); padding:28px; }}
    h1 {{ margin:0 0 8px; font-size:22px; }}
    p {{ color:rgba(245,240,232,.66); line-height:1.55; }}
    code {{ color:#00e5c8; }}
  </style>
</head>
<body>
  <main>
    <h1>Completing Interlock sign-in</h1>
    <p>Forwarding the Supabase Auth token to <code>{TARGET}</code>.</p>
  </main>
  <script>
    const target = "{TARGET}";
    const suffix = window.location.hash || window.location.search || "";
    window.location.replace(target + suffix);
  </script>
</body>
</html>"""

class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = HTML.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        print("[supabase-auth-redirect] " + fmt % args)

if __name__ == "__main__":
    server = ThreadingHTTPServer(("0.0.0.0", 3000), Handler)
    print(f"Supabase Auth redirect shim running on http://localhost:3000 -> {TARGET}")
    server.serve_forever()

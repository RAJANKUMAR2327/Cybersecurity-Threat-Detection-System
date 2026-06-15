path = r'dashboard\dashboard_server.py'

with open(path) as f:
    content = f.read()

fix = """
@app.route('/')
def index():
    import os
    return send_file(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'index.html'))

"""

if '@app.route("/")' not in content:
    content = content.replace('@app.route("/api/status")', fix + '@app.route("/api/status")')
    with open(path, 'w') as f:
        f.write(content)
    print('FIXED!')
else:
    print('Route already exists.')
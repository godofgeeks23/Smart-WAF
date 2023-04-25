from http.server import HTTPServer, SimpleHTTPRequestHandler

class SimpleHTTPProxy(SimpleHTTPRequestHandler):
    proxy_routes = {}
    @classmethod
    def set_routes(cls, proxy_routes):
        cls.proxy_routes = proxy_routes
    def do_GET(self):
        parts = self.path.split('/')
        print(parts)
        

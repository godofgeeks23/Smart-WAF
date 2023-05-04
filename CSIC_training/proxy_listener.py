from mitmproxy import http
from mitmproxy import ctx

class Blocker:
    def __init__(self):
        self.blocked = False

    def request(self, flow: http.HTTPFlow) -> None:
        if self.blocked:
            flow.kill()
            ctx.log.warn(f"Blocked request to {flow.request.pretty_url}")
        else:
            ctx.log.info(f"Request to {flow.request.pretty_url}")

    def response(self, flow: http.HTTPFlow) -> None:
        ctx.log.info(f"Response from {flow.request.pretty_url}")

addons = [
    Blocker()
]

def start():
    print("Starting proxy listener...")
    print("Type 'block' to block requests, 'unblock' to unblock.")
    print("Type 'exit' to stop the proxy listener.")
    while True:
        cmd = input("> ")
        if cmd == "block":
            addons[0].blocked = True
            print("Requests blocked.")
        elif cmd == "unblock":
            addons[0].blocked = False
            print("Requests unblocked.")
        elif cmd == "exit":
            break
        else:
            print(f"Unknown command: {cmd}")

if __name__ == "__main__":
    start()

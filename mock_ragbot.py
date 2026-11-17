"""Simulador del RAG PDFBot VULNERABLE (mismos endpoints y comportamiento) para probar AI Guardian sin LLM real.
Sin auth, sin límites, memoria compartida, obedece instrucciones del contexto y del usuario, devuelve str(e)."""
import json, re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
MEMORY = []  # memoria compartida por todos (como Chroma por proveedor)

def pdf_text(raw: bytes) -> str:
    return " ".join(re.findall(rb"\((.*?)\)\s*Tj", raw, re.S)[i].decode("latin-1") for i in range(len(re.findall(rb"\((.*?)\)\s*Tj", raw, re.S))))

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def send(self, code, obj):
        b = json.dumps(obj).encode(); self.send_response(code); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        if self.path == "/docs": self.send_response(200); self.end_headers(); self.wfile.write(b"<html>Swagger UI</html>")
        elif self.path == "/llm": self.send(200, {"status": "success", "data": ["Groq", "Gemini"]})
        else: self.send(200, {"status": "success", "data": "ok"})
    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        if self.path == "/upload_and_process_pdfs":
            if b"filename=" in raw and b".pdf" in raw:  # solo mira la extensión
                MEMORY.append(pdf_text(raw) or raw.decode("latin-1")[:500])
                return self.send(200, {"status": "success", "data": "PDFs processed successfully."})
            return self.send(200, {"status": "error", "message": "not a valid PDF file."})
        body = json.loads(raw or b"{}")
        if self.path == "/vector_store/search":
            if body.get("model_provider") not in ("groq", "gemini"):
                return self.send(200, {"status": "error", "message": f"'{body.get('model_provider')}'"})  # KeyError filtrado
            return self.send(200, {"status": "success", "data": [{"page_content": m} for m in MEMORY[-3:]]})
        if self.path == "/chat":
            msg = body.get("message", ""); ctx = " ".join(MEMORY[-3:])
            out = "Answer as detailed as possible using the context below. " if "system prompt" in msg.lower() else ""
            for src in (msg, ctx):                       # obedece instrucciones en usuario y contexto
                for m in re.findall(r"(ZDT-[A-Z]+-[\w-]+)", src): out += f" {m}"
            if "![" in msg: out += re.search(r"!\[[^\]]*\]\([^)]*\)", msg).group(0)
            if "vacaciones" in msg.lower(): out += " La politica indica 23 dias laborables."
            return self.send(200, {"status": "success", "data": out.strip() or "I don't know."})
        self.send(404, {"detail": "Not Found"})

if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", 8765), H).serve_forever()

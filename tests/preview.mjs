import http from 'node:http';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const server = http.createServer(async (request, response) => {
  if (request.url !== '/') { response.writeHead(404); response.end(); return; }
  try {
    const body = await readFile(path.join(root, 'freessl.html'));
    response.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
    response.end(body);
  } catch { response.writeHead(500); response.end('Preview unavailable'); }
});
server.listen(0, '127.0.0.1', () => console.log('Preview: http://127.0.0.1:' + server.address().port + '/'));

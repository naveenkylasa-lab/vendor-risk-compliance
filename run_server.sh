#!/usr/bin/env bash
# Starts the Vendor Risk & Compliance server on http://127.0.0.1:8000
# Uses Python FastAPI/Uvicorn when available, or macOS built-in Ruby HTTP server as a zero-dependency fallback.

set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
PORT="${PORT:-8000}"

if python3 -c "import uvicorn, fastapi" >/dev/null 2>&1; then
  exec python3 -m uvicorn app.main:app --host 127.0.0.1 --port "$PORT"
fi

exec /usr/bin/ruby -E UTF-8:UTF-8 - "$PORT" "$SCRIPT_DIR/app/static/index.html" <<'RUBY_EOF'
# encoding: UTF-8
require 'socket'
require 'json'

port = (ARGV[0] || 8000).to_i
index_path = ARGV[1]

server = TCPServer.new('127.0.0.1', port)
puts "SentinelTPRM Server listening on http://127.0.0.1:#{port}"
STDOUT.flush

loop do
  client = server.accept
  Thread.new(client) do |sock|
    begin
      request_line = sock.gets
      next unless request_line
      method, path, _ = request_line.split(' ')
      headers = {}
      while (line = sock.gets) && line != "\r\n"
        k, v = line.split(':', 2)
        headers[k.downcase.strip] = v.strip if v
      end
      if headers['content-length']
        _body = sock.read(headers['content-length'].to_i)
      end

      clean_path = (path || "/").split('?').first

      if (method == 'GET' || method == 'HEAD') && (clean_path == '/' || clean_path == '/index.html')
        html = File.read(index_path, encoding: 'UTF-8')
        sock.print "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: #{html.bytesize}\r\nConnection: close\r\n\r\n"
        sock.print html if method == 'GET'
      else
        sock.print "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
      end
    rescue => _e
    ensure
      sock.close rescue nil
    end
  end
end
RUBY_EOF

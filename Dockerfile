# Parro MCP as a remote server.
#
# parro_mcp.py speaks stdio only. mcp-auth-proxy wraps it in an OAuth 2.1 layer
# (protected-resource metadata, PKCE, dynamic client registration) and serves it
# over HTTP, which is what Claude on the web and the phone need to connect.
FROM ghcr.io/sigbit/mcp-auth-proxy:latest AS auth

FROM python:3.12-slim

# PDF text and photos from attachments - the reason to read Parro at all.
RUN pip install --no-cache-dir pymupdf pillow

COPY --from=auth /usr/local/bin/mcp-auth-proxy /usr/local/bin/mcp-auth-proxy
COPY parro_mcp.py /app/parro_mcp.py

# /data carries both the proxy's OAuth state and the Parro token cache, so it
# has to be a volume: without one, every deploy logs you out of both.
ENV DATA_PATH=/data \
    PARRO_TOKEN_FILE=/data/parro-tokens.json
RUN mkdir -p /data

EXPOSE 80
ENTRYPOINT ["/usr/local/bin/mcp-auth-proxy"]
CMD ["--", "python", "/app/parro_mcp.py"]

# Static single-page app served by the non-root nginx image: it listens on
# the unprivileged port 8080 as UID 101 (AGENTS.md invariant 13).
#
# The base image is pinned by tag *and* digest: the tag documents the intended
# release, the digest guarantees the exact bits. To bump it:
#   docker buildx imagetools inspect docker.io/nginxinc/nginx-unprivileged:1.31.5-alpine
FROM docker.io/nginxinc/nginx-unprivileged:1.31.7-alpine@sha256:378d0c32f6562f7fd9629170797f57d2b953aa09be983b3daaf4809bb039ca00

COPY index.html styles.css app.js config.js /usr/share/nginx/html/
COPY nginx.conf /etc/nginx/conf.d/default.conf
# Shared security headers (CSP, Permissions-Policy, ...) included by nginx.conf.
COPY security-headers.conf /etc/nginx/snippets/security-headers.conf

USER 101

EXPOSE 8080

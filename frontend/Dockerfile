# Static single-page app served by the non-root nginx image (listens on 8080).
FROM docker.io/nginx:trixie

COPY index.html styles.css app.js config.js /usr/share/nginx/html/
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

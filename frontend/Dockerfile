FROM nginx:1.27-alpine

# Static single-page app (no build step).
COPY index.html styles.css app.js config.js /usr/share/nginx/html/
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80

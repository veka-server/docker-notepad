# Utiliser l'image officielle PHP avec Apache
FROM php:8.3-apache

RUN apt-get update && apt-get install -y \
    libsqlite3-dev \
    && docker-php-ext-install pdo pdo_sqlite \
    && a2enmod rewrite \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Copier le contenu du site dans le répertoire par défaut d'Apache
COPY src/ /var/www/html/

# Modifier les permissions pour que Apache puisse accéder aux fichiers
RUN chown -R www-data:www-data /var/www/html \
    && chmod -R 755 /var/www/html

USER www-data

# Exposer le port 80 pour accéder à l'application
EXPOSE 80

VOLUME /var/www/html/db

# Lancer Apache en mode "foreground"
CMD ["apache2-foreground"]

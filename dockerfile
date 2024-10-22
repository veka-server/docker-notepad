# Utiliser l'image officielle PHP avec Apache
FROM php:8.3-apache

RUN docker-php-ext-install sqlite

# Activer le module de réécriture Apache (utile pour .htaccess si nécessaire)
RUN a2enmod rewrite

# Copier le contenu du site dans le répertoire par défaut d'Apache
COPY src/ /var/www/html/

# Modifier les permissions pour que Apache puisse accéder aux fichiers
RUN chown -R www-data:www-data /var/www/html \
    && chmod -R 755 /var/www/html

# Exposer le port 80 pour accéder à l'application
EXPOSE 80

# Lancer Apache en mode "foreground"
CMD ["apache2-foreground"]

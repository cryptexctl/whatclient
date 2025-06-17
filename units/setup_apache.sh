#!/bin/bash
a2enmod proxy
a2enmod proxy_http
a2enmod ssl
a2enmod rewrite
cp exteraapi.conf /etc/apache2/sites-available/
a2ensite exteraapi.conf
systemctl restart apache2 
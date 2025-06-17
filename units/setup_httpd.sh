#!/bin/bash
dnf install -y httpd mod_ssl
mkdir -p /etc/httpd/conf.d/
cp exteraapi.conf /etc/httpd/conf.d/
systemctl enable httpd
systemctl restart httpd
firewall-cmd --permanent --add-service=http
firewall-cmd --permanent --add-service=https
firewall-cmd --reload 
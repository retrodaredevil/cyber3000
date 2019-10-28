apt-get install auditd && \
auditctl -e 1 && \
printf "Enabled auditctl! Make sure to view and modify policies located at /etc/audit/auditd.conf"
printf "\n"

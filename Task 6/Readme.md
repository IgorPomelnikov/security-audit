# Аудит активности пользователей и обнаружение инцидентов

## Подготовка 

minikube stop
minikube delete

mkdir -p ~/.minikube/files/etc/ssl/certs

cp "./audit-policy.yaml" ~/.minikube/files/etc/ssl/certs/audit-policy.yaml

minikube start\
 --extra-config=apiserver.audit-policy-file=/etc/ssl/certs/audit-policy.yaml --extra-config=apiserver.audit-log-path=/var/log/audit.log

пробуем атаковать:

chmod +x simulate-icident.sh
./simulate-incident.sh

копируем логи:

minikube ssh 'PATH_TO_AUDITLOG=$(sudo find /var/lib/docker/overlay2 -name "audit.log" -path "*/merged/var/log/audit.log" | head -1); sudo cat "$PATH_TO_AUDITLOG"' > audit.log

проводим анализ логов:

chmod +x make-analysis.py
./make-analysis.py audit.log

P.S. Текущий анализатор логов нуждается в доработке, потому что он пропускает некоторые критические события типа создания подов. Но смысл работы с логами понятен
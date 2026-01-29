# Отчёт по результатам анализа Kubernetes Audit Log
## Дата генерации: 2026-01-29 10:28:51
## Всего событий: 6799

## Подозрительные события

1. Доступ к секретам:
   - Кто: minikube-user
   - Где: неймспейс kube-system, ресурс unknown
   - Почему подозрительно: перечисление секретов
   - Время: 2026-01-29T09:25:17.843637Z
   - Источник: 192.168.49.1

   - Кто: minikube-user
   - Где: неймспейс kube-system, ресурс unknown
   - Почему подозрительно: перечисление секретов
   - Время: 2026-01-29T09:25:17.843637Z
   - Источник: 192.168.49.1

   - Кто: minikube-user
   - Где: неймспейс kube-system, ресурс unknown
   - Почему подозрительно: перечисление секретов
   - Время: 2026-01-29T09:25:17.925986Z
   - Источник: 192.168.49.1

   - Кто: minikube-user
   - Где: неймспейс kube-system, ресурс unknown
   - Почему подозрительно: перечисление секретов
   - Время: 2026-01-29T09:25:17.925986Z
   - Источник: 192.168.49.1

   - Кто: minikube-user
   - Где: неймспейс kube-system, ресурс unknown
   - Почему подозрительно: перечисление секретов
   - Время: 2026-01-29T09:36:20.232070Z
   - Источник: 192.168.49.1

   - Кто: minikube-user
   - Где: неймспейс kube-system, ресурс unknown
   - Почему подозрительно: перечисление секретов
   - Время: 2026-01-29T09:36:20.232070Z
   - Источник: 192.168.49.1

   - Кто: minikube-user
   - Где: неймспейс kube-system, ресурс unknown
   - Почему подозрительно: перечисление секретов
   - Время: 2026-01-29T09:36:20.322771Z
   - Источник: 192.168.49.1

   - Кто: minikube-user
   - Где: неймспейс kube-system, ресурс unknown
   - Почему подозрительно: перечисление секретов
   - Время: 2026-01-29T09:36:20.322771Z
   - Источник: 192.168.49.1

2. Привилегированные поды:
   - Кто: system:node:minikube
   - Под: kube-scheduler-minikube в неймспейсе kube-system
   - Комментарий: hostPath volume: /etc/kubernetes/scheduler.conf

   - Кто: system:node:minikube
   - Под: etcd-minikube в неймспейсе kube-system
   - Комментарий: hostPath volume: /var/lib/minikube/certs/etcd, hostPath volume: /var/lib/minikube/etcd

   - Кто: system:node:minikube
   - Под: kube-apiserver-minikube в неймспейсе kube-system
   - Комментарий: hostPath volume: /etc/ssl/certs, hostPath volume: /etc/ca-certificates, hostPath volume: /var/lib/minikube/certs, hostPath volume: /usr/local/share/ca-certificates, hostPath volume: /usr/share/ca-certificates

   - Кто: system:node:minikube
   - Под: kube-controller-manager-minikube в неймспейсе kube-system
   - Комментарий: hostPath volume: /etc/ssl/certs, hostPath volume: /etc/ca-certificates, hostPath volume: /usr/libexec/kubernetes/kubelet-plugins/volume/exec, hostPath volume: /var/lib/minikube/certs, hostPath volume: /etc/kubernetes/controller-manager.conf, hostPath volume: /usr/local/share/ca-certificates, hostPath volume: /usr/share/ca-certificates

   - Кто: system:node:minikube
   - Под: etcd-minikube в неймспейсе kube-system
   - Комментарий: hostPath volume: /var/lib/minikube/certs/etcd, hostPath volume: /var/lib/minikube/etcd

   - Кто: system:node:minikube
   - Под: kube-apiserver-minikube в неймспейсе kube-system
   - Комментарий: hostPath volume: /etc/ssl/certs, hostPath volume: /etc/ca-certificates, hostPath volume: /var/lib/minikube/certs, hostPath volume: /usr/local/share/ca-certificates, hostPath volume: /usr/share/ca-certificates

   - Кто: system:node:minikube
   - Под: kube-scheduler-minikube в неймспейсе kube-system
   - Комментарий: hostPath volume: /etc/kubernetes/scheduler.conf

   - Кто: system:node:minikube
   - Под: kube-apiserver-minikube в неймспейсе kube-system
   - Комментарий: hostPath volume: /etc/ssl/certs, hostPath volume: /etc/ca-certificates, hostPath volume: /var/lib/minikube/certs, hostPath volume: /usr/local/share/ca-certificates, hostPath volume: /usr/share/ca-certificates

   - Кто: system:node:minikube
   - Под: kube-scheduler-minikube в неймспейсе kube-system
   - Комментарий: hostPath volume: /etc/kubernetes/scheduler.conf

   - Кто: system:node:minikube
   - Под: etcd-minikube в неймспейсе kube-system
   - Комментарий: hostPath volume: /var/lib/minikube/certs/etcd, hostPath volume: /var/lib/minikube/etcd

3. Использование kubectl exec в подах:
   - Кто: minikube-user
   - Что делал: exec в под coredns-66bc5c9577-45mrt (команда: unknown)
   - Неймспейс: kube-system

   - Кто: minikube-user
   - Что делал: exec в под coredns-66bc5c9577-45mrt (команда: unknown)
   - Неймспейс: kube-system

   - Кто: minikube-user
   - Что делал: exec в под coredns-66bc5c9577-45mrt (команда: unknown)
   - Неймспейс: kube-system

   - Кто: minikube-user
   - Что делал: exec в под coredns-66bc5c9577-45mrt (команда: unknown)
   - Неймспейс: kube-system

   - Кто: minikube-user
   - Что делал: exec в под coredns-66bc5c9577-45mrt (команда: unknown)
   - Неймспейс: kube-system

   - Кто: minikube-user
   - Что делал: exec в под coredns-66bc5c9577-45mrt (команда: unknown)
   - Неймспейс: kube-system

4. Создание RoleBinding с правами cluster-admin:
   - Подозрительных событий не обнаружено

5. Удаление audit-policy:
   - Подозрительных событий не обнаружено

## Вывод
Обнаружено 35 подозрительных событий:
  - доступ к секретам: 8 событий
  - привилегированные поды: 21 событий
  - exec в подах: 6 событий

Рекомендации:
1. Провести детальный анализ событий, отмеченных как подозрительные
2. Проверить настройки RBAC и ограничить привилегии пользователей
3. Убедиться, что политика аудита не была скомпрометирована
4. Проверить поды с привилегированным доступом на соответствие политикам безопасности
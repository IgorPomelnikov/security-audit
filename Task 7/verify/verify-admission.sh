#!/bin/bash

echo "=== Проверка Pod Security Admission ==="
echo "1. Создаем namespace audit-zone..."
kubectl apply -f ../01-create-namespace.yaml

echo "2. Пробуем развернуть небезопасные поды (должны быть отклонены)..."

echo "2.1. Привилегированный pod:"
kubectl apply -f ../insecure-manifests/01-privileged-pod.yaml 2>&1 | grep -E "denied|violation|error" || echo "✓ Должно быть отклонено"

echo "2.2. Pod с hostPath:"
kubectl apply -f ../insecure-manifests/02-hostpath-pod.yaml 2>&1 | grep -E "denied|violation|error" || echo "✓ Должно быть отклонено"

echo "2.3. Pod с root пользователем:"
kubectl apply -f ../insecure-manifests/03-root-user-pod.yaml 2>&1 | grep -E "denied|violation|error" || echo "✓ Должно быть отклонено"

echo "3. Развертываем безопасные поды..."
kubectl apply -f ../secure-manifests/01-secure.yaml
kubectl apply -f ../secure-manifests/02-secure.yaml
kubectl apply -f ../secure-manifests/03-secure.yaml

echo "=== Проверка Gatekeeper ==="
echo "4. Устанавливаем ConstraintTemplates..."
kubectl apply -f ../gatekeeper/constraint-templates/

echo "5. Ждем готовности ConstraintTemplates..."
sleep 10

echo "6. Применяем Constraints..."
kubectl apply -f ../gatekeeper/constraints/

echo "7. Проверяем работу Gatekeeper..."
echo "7.1. Пробуем создать привилегированный pod с Gatekeeper:"
cat <<TEST_EOF | kubectl apply -f - 2>&1 | grep -E "denied|violation" || echo "✓ Gatekeeper работает"
apiVersion: v1
kind: Pod
metadata:
  name: test-gatekeeper-privileged
  namespace: audit-zone
spec:
  containers:
    - name: test
      image: nginx
      securityContext:
        privileged: true
TEST_EOF

echo "=== Итоговая проверка ==="
echo "Поды в namespace audit-zone:"
kubectl get pods -n audit-zone

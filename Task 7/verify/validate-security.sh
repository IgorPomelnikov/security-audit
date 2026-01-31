#!/bin/bash

echo "=== Валидация конфигурации безопасности ==="

echo "1. Проверяем метки namespace:"
kubectl get namespace audit-zone -o jsonpath='{.metadata.labels}' | jq . 2>/dev/null || echo "Namespace не найден или jq не установлен"

echo "2. Проверяем ConstraintTemplates:"
kubectl get constrainttemplates 2>/dev/null || echo "ConstraintTemplates не найдены или Gatekeeper не установлен"

echo "3. Проверяем Constraints:"
kubectl get constraints 2>/dev/null || echo "Constraints не найдены"

echo "4. Проверяем политики безопасности подов:"
kubectl get pods -n audit-zone -o jsonpath='{range .items[*]}{.metadata.name}{": "}{.spec.containers[*].securityContext}{"\n"}{end}' 2>/dev/null || echo "Поды не найдены"

echo "5. Проверяем Volume types:"
kubectl get pods -n audit-zone -o jsonpath='{range .items[*]}{.metadata.name}{": "}{.spec.volumes[*]}{"\n"}{end}' 2>/dev/null || echo "Поды не найдены"

echo "6. Проверяем метки Pod Security:"
kubectl describe namespace audit-zone | grep -A5 "Labels:"

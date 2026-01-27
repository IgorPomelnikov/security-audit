#!/bin/bash
# Создание пользователя через Kubernetes CSR API.

set -euo pipefail  # Безопасное выполнение

show_usage() {
    echo "Использование: $0 <имя_пользователя> <группа1>[,<группа2>,...]"
    echo ""
    echo "Пример: $0 alice developers,viewers"
    exit 1
}

# Проверка аргументов
if [[ $# -lt 2 ]]; then
    echo "Ошибка: недостаточно аргументов"
    echo ""
    show_usage
fi

USER="$1"
IFS=',' read -r -a GROUPS <<< "$2"

# Проверка имени пользователя
if [[ ! "$USER" =~ ^[a-zA-Z0-9][a-zA-Z0-9._-]*$ ]]; then
    echo "Ошибка: некорректное имя пользователя"
    exit 1
fi

WORKDIR="./certs/${USER}"
mkdir -p "$WORKDIR"

echo "Создание пользователя: $USER"
echo "Группы: ${GROUPS[*]}"
echo "Рабочая директория: $WORKDIR"
echo ""

# 1) Генерируем ключ и CSR (с множественными O= для групп)
echo "Генерация приватного ключа..."
openssl genrsa -out "${WORKDIR}/${USER}.key" 2048

# Формируем subject: /CN=<user>/O=<group1>/O=<group2>/...
SUBJ="/CN=${USER}"
for g in "${GROUPS[@]}"; do
    SUBJ="${SUBJ}/O=${g}"
done

echo "Создание CSR..."
openssl req -new \
    -key "${WORKDIR}/${USER}.key" \
    -out "${WORKDIR}/${USER}.csr" \
    -subj "${SUBJ}"

# 2) Создаём объект CSR в Kubernetes
echo "Создание манифеста CSR..."
cat > "${WORKDIR}/${USER}-csr.yaml" <<EOF
apiVersion: certificates.k8s.io/v1
kind: CertificateSigningRequest
metadata:
  name: ${USER}-csr
spec:
  request: $(base64 < "${WORKDIR}/${USER}.csr" | tr -d '\n')
  signerName: kubernetes.io/kube-apiserver-client
  usages:
  - client auth
EOF

# Удаляем старый CSR если существует
echo "Очистка предыдущего CSR (если есть)..."
kubectl delete csr "${USER}-csr" --ignore-not-found=true

echo "Применение CSR..."
kubectl apply -f "${WORKDIR}/${USER}-csr.yaml"

# 3) Одобряем CSR и получаем сертификат
echo "Одобрение CSR..."
kubectl certificate approve "${USER}-csr"

echo "Получение сертификата..."
kubectl get csr "${USER}-csr" -o jsonpath='{.status.certificate}' | base64 -d > "${WORKDIR}/${USER}.crt"

# Проверка сертификата
if [[ -s "${WORKDIR}/${USER}.crt" ]]; then
    echo ""
    echo "=========================================="
    echo "Сертификат успешно создан!"
    echo "Пути к файлам:"
    echo "  Приватный ключ: ${WORKDIR}/${USER}.key"
    echo "  Сертификат:     ${WORKDIR}/${USER}.crt"
    echo "  CSR:            ${WORKDIR}/${USER}.csr"
    echo "  Манифест:       ${WORKDIR}/${USER}-csr.yaml"
    echo ""
    echo "Для настройки kubectl выполните:"
    echo "kubectl config set-credentials ${USER} \\"
    echo "  --client-certificate=${WORKDIR}/${USER}.crt \\"
    echo "  --client-key=${WORKDIR}/${USER}.key"
    echo "=========================================="
else
    echo "Ошибка: не удалось получить сертификат"
    exit 1
fi
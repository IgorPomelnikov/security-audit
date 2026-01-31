#!/bin/bash
# Генерация kubeconfig для пользователя.

set -euo pipefail  # Безопасное выполнение

show_usage() {
    echo "Использование: $0 <имя_пользователя>"
    echo ""
    echo "Пример: $0 alice"
    echo ""
    echo "Предварительно выполните: ./40-create-user.sh <username> <groups>"
    exit 1
}

# Проверка аргументов
if [[ $# -lt 1 ]]; then
    echo "Ошибка: недостаточно аргументов"
    echo ""
    show_usage
fi

USER="$1"
WORKDIR="./certs/${USER}"

# Проверка существования сертификата
if [[ ! -f "${WORKDIR}/${USER}.crt" ]]; then
    echo "Ошибка: сертификат пользователя не найден: ${WORKDIR}/${USER}.crt"
    echo ""
    echo "Сначала выполните скрипт создания пользователя:"
    echo "  ./40-create-user.sh ${USER} <группы>"
    exit 1
fi

if [[ ! -f "${WORKDIR}/${USER}.key" ]]; then
    echo "Ошибка: приватный ключ не найден: ${WORKDIR}/${USER}.key"
    exit 1
fi

echo "Генерация kubeconfig для пользователя: $USER"
echo "Рабочая директория: $WORKDIR"
echo ""

# Получаем параметры текущего кластера из kubectl
echo "Получение информации о кластере..."
CLUSTER_NAME=$(kubectl config view -o jsonpath='{.clusters[0].name}')
CLUSTER_SERVER=$(kubectl config view -o jsonpath='{.clusters[0].cluster.server}')

if [[ -z "$CLUSTER_NAME" ]] || [[ -z "$CLUSTER_SERVER" ]]; then
    echo "Ошибка: не удалось получить информацию о кластере"
    echo "Проверьте конфигурацию kubectl"
    exit 1
fi

echo "  Кластер: $CLUSTER_NAME"
echo "  Сервер:  $CLUSTER_SERVER"

# Создаём временный файл для CA
CLUSTER_CA=$(mktemp)
trap 'rm -f "$CLUSTER_CA"' EXIT  # Автоматически удаляем при выходе

echo "Получение CA сертификата..."
kubectl config view --raw -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' | base64 -d > "$CLUSTER_CA"

if [[ ! -s "$CLUSTER_CA" ]]; then
    echo "Ошибка: не удалось получить CA сертификат"
    exit 1
fi

KCONF="${WORKDIR}/${USER}-kubeconfig.yaml"

echo ""
echo "Создание kubeconfig..."

# 1. Настройка кластера
echo "  Настройка кластера..."
kubectl config --kubeconfig="$KCONF" set-cluster "$CLUSTER_NAME" \
    --server="$CLUSTER_SERVER" \
    --certificate-authority="$CLUSTER_CA" \
    --embed-certs=true

# 2. Настройка пользователя
echo "  Настройка учётных данных пользователя..."
kubectl config --kubeconfig="$KCONF" set-credentials "$USER" \
    --client-certificate="${WORKDIR}/${USER}.crt" \
    --client-key="${WORKDIR}/${USER}.key" \
    --embed-certs=true

# 3. Настройка контекста
echo "  Настройка контекста..."
kubectl config --kubeconfig="$KCONF" set-context "${USER}@${CLUSTER_NAME}" \
    --cluster="$CLUSTER_NAME" \
    --user="$USER"

# 4. Установка текущего контекста
echo "  Установка текущего контекста..."
kubectl config --kubeconfig="$KCONF" use-context "${USER}@${CLUSTER_NAME}"

echo ""
echo "=========================================="
echo "Kubeconfig успешно создан!"
echo ""
echo "Файл: $KCONF"
echo ""
echo "Для использования выполните:"
echo "  export KUBECONFIG=\"$KCONF\""
echo ""
echo "Или используйте с kubectl:"
echo "  kubectl --kubeconfig=\"$KCONF\" get pods"
echo ""
echo "Для проверки конфигурации:"
echo "  kubectl --kubeconfig=\"$KCONF\" config view"
echo ""
echo "Текущий контекст:"
echo "  kubectl --kubeconfig=\"$KCONF\" config current-context"
echo "=========================================="

# Дополнительная проверка
echo ""
echo "Проверка доступа к кластеру..."
if timeout 10s kubectl --kubeconfig="$KCONF" cluster-info > /dev/null 2>&1; then
    echo "  ✓ Успешное подключение к кластеру"
else
    echo "  ⚠ Не удалось подключиться к кластеру"
    echo "  Проверьте права доступа пользователя"
fi
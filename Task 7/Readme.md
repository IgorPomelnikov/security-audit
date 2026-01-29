

# Отчистить от предыдущих запусков
kubectl delete ns audit-zone --ignore-not-found=true
kubectl delete -f gatekeeper/constraints/ --ignore-not-found=true || true
kubectl delete -f gatekeeper/constraint-templates/ --ignore-not-found=true || true
kubectl delete -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/master/deploy/gatekeeper.yaml --ignore-not-found=true || true
kubectl delete pod pod-privileged pod-hostpath pod-root pod-secure-1 pod-secure-2 pod-secure-3 --ignore-not-found=true
kubectl delete crd constrainttemplates.templates.gatekeeper.sh --ignore-not-found=true || true
kubectl delete crd k8shostpaths.constraints.gatekeeper.sh --ignore-not-found=true || true
kubectl delete crd k8sprivilegeds.constraints.gatekeeper.sh --ignore-not-found=true || true
kubectl delete crd k8srunasnonroots.constraints.gatekeeper.sh --ignore-not-found=true || true
kubectl delete crd k8sreadonlyrootfilesystems.constraints.gatekeeper.sh --ignore-not-found=true || true
minikube stop
minikube delete

# Произвести запуск

mkdir -p ~/.minikube/files/etc/ssl/certs
cp "./audit-policy.yaml" ~/.minikube/files/etc/ssl/certs/audit-policy.yaml
minikube start\
 --extra-config=apiserver.audit-policy-file=/etc/ssl/certs/audit-policy.yaml --extra-config=apiserver.audit-log-path=/var/log/audit.log
kubectl apply -f 01-create-namespace.yaml
kubectl apply -f https://raw.githubusercontent.com/open-policy-agent/gatekeeper/master/deploy/gatekeeper.yaml

# Применить ограничения

kubectl apply -f gatekeeper/constraint-templates/ 
kubectl apply -f gatekeeper/constraints/

# Проверить небезопасные контейнеры

kubectl apply -f insecure-manifests/

# Проверить безопасные контейнеры 

kubectl apply -f secure-manifests/


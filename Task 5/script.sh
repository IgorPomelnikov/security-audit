NAMESPACE="network-task"
kubectl create namespace $NAMESPACE || true
kubectl run front-end-app --image=nginx -n $NAMESPACE --labels role=front-end --port=80 --expose
kubectl run back-end-api-app --image=nginx -n $NAMESPACE --labels role=back-end-api --port=80 --expose
kubectl run admin-front-end-app --image=nginx -n $NAMESPACE --labels role=admin-front-end --port=80 --expose
kubectl run admin-back-end-api-app --image=nginx -n $NAMESPACE --labels role=admin-back-end-api --port=80 --expose
kubectl run internal-app --image=nginx -n $NAMESPACE --labels role=internal --port=80 --expose
kubectl apply -f non-admin-api-allow.yaml -n $NAMESPACE

#!/bin/bash

helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo update
helm upgrade --create-namespace --install prometheus prometheus-community/kube-prometheus-stack  -n prometheus-operator --values prometheus-operator-values.yaml

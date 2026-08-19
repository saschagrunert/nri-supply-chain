{{- define "nri-supply-chain.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "nri-supply-chain.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := include "nri-supply-chain.name" . }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "nri-supply-chain.namespace" -}}
{{- default .Release.Namespace .Values.namespaceOverride }}
{{- end }}

{{- define "nri-supply-chain.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "nri-supply-chain.labels" -}}
helm.sh/chart: {{ include "nri-supply-chain.chart" . }}
app.kubernetes.io/name: {{ include "nri-supply-chain.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "nri-supply-chain.selectorLabels" -}}
app.kubernetes.io/name: {{ include "nri-supply-chain.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "nri-supply-chain.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "nri-supply-chain.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- required "serviceAccount.name is required when serviceAccount.create is false" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "nri-supply-chain.metricsPort" -}}
{{- $match := regexFind ":[0-9]+$" .Values.config.metricsAddr -}}
{{- if not $match -}}
{{- fail "config.metricsAddr must end with :<port>" -}}
{{- end -}}
{{- $port := trimPrefix ":" $match | int -}}
{{- if or (lt $port 1) (gt $port 65535) -}}
{{- fail "config.metricsAddr port must be between 1 and 65535" -}}
{{- end -}}
{{- $port -}}
{{- end }}

{{- define "iptables-exporter.name" -}}iptables-exporter{{- end -}}
{{- define "iptables-exporter.labels" -}}
app.kubernetes.io/name: {{ include "iptables-exporter.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end -}}

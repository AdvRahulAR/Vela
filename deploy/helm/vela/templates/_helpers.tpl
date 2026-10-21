{{- define "vela.fullname" -}}{{ .Release.Name }}-vela{{- end -}}
{{- define "vela.selectorLabels" -}}
app.kubernetes.io/name: vela
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
{{- define "vela.labels" -}}
{{ include "vela.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end -}}

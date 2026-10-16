{{- define "spiffex.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "spiffex.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{- define "spiffex.selectorLabels" -}}
app.kubernetes.io/name: {{ include "spiffex.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "spiffex.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{ include "spiffex.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/component: issuer
{{- end }}

{{- define "spiffex.tlsEnabled" -}}
{{- if or .Values.tls.existingSecret .Values.tls.certManager.enabled }}true{{ end }}
{{- end }}

{{- define "spiffex.tlsSecret" -}}
{{- if .Values.tls.existingSecret }}{{ .Values.tls.existingSecret }}{{ else }}{{ include "spiffex.fullname" . }}-tls{{ end }}
{{- end }}

{{- define "spiffex.host" -}}
{{ include "spiffex.fullname" . }}.{{ .Release.Namespace }}.svc
{{- end }}

{{- define "spiffex.issuer" -}}
{{- if .Values.issuer }}
{{- .Values.issuer }}
{{- else if include "spiffex.tlsEnabled" . }}
{{- printf "https://%s" (include "spiffex.host" .) }}
{{- else }}
{{- fail "issuer is required without TLS: give the URL of the proxy in front of the issuer, or set tls.existingSecret or tls.certManager" }}
{{- end }}
{{- end }}

{{- define "spiffex.stateConfigMap" -}}
{{- default (printf "%s-state" (include "spiffex.fullname" .)) .Values.state.existingConfigMap }}
{{- end }}

{{- define "spiffex.servicePort" -}}
{{- if .Values.service.port }}{{ .Values.service.port }}{{ else if include "spiffex.tlsEnabled" . }}443{{ else }}80{{ end }}
{{- end }}

{{- define "spiffex.image" -}}
{{- if .Values.image.digest }}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest }}
{{- else }}
{{- printf "%s:%s" .Values.image.repository (default (printf "v%s" .Chart.AppVersion) .Values.image.tag) }}
{{- end }}
{{- end }}

{{/* The issuer's settings file. */}}
{{- define "spiffex.settings" -}}
issuer: {{ include "spiffex.issuer" . | quote }}
trust_domain: {{ required "trustDomain is required" .Values.trustDomain | quote }}
keys_dir: /keys
token_ttl: {{ .Values.tokenTTL | quote }}
activation_delay: {{ .Values.activationDelay | quote }}
state:
  configmap:
    namespace: {{ .Release.Namespace | quote }}
    name: {{ include "spiffex.stateConfigMap" . | quote }}
management: {{ .Values.management }}
fetch:
  refuse_private_addresses: {{ .Values.fetch.refusePrivateAddresses }}
  allow_private_hosts: {{ .Values.fetch.allowPrivateHosts | default list | toJson }}
{{- if hasKey .Values "readableFiles" }}
readable_files: {{ .Values.readableFiles | default list | toJson }}
{{- end }}
{{- if hasKey .Values "bearerTokenFiles" }}
bearer_token_files: {{ .Values.bearerTokenFiles | default list | toJson }}
{{- end }}
{{- with .Values.verifiers }}
verifiers: {{ toJson . }}
{{- end }}
{{- with .Values.verifierLimits }}
{{- $limits := . }}
verifier_limits:
  {{- range $key, $field := dict "perOrigin" "per_origin" "total" "total" "perAddressPerMinute" "per_address_per_minute" "perAddressBurst" "per_address_burst" }}
  {{- if hasKey $limits $key }}
  {{ $field }}: {{ index $limits $key | int }}
  {{- end }}
  {{- end }}
{{- end }}
{{- with .Values.verifierUser }}
verifier_user: {{ toJson . }}
{{- end }}
{{- with .Values.trustedProxies }}
trusted_proxies: {{ toJson . }}
{{- end }}
{{- end }}

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
{{- if .Values.ingress.enabled }}
{{- $want := printf "https://%s" (required "ingress.host is required with ingress.enabled" .Values.ingress.host) }}
{{- if ne .Values.issuer $want }}
{{- fail (printf "issuer must be %s, not %q: with ingress.enabled, clients reach the issuer at the ingress host, and tokens must carry that URL as iss" $want .Values.issuer) }}
{{- end }}
{{- end }}
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

{{/* The name of the object holding ca_roots, or nothing without roots. */}}
{{- define "spiffex.caRoots" -}}
{{- $roots := .Values.ca.roots }}
{{- if and $roots.configMap $roots.secret }}
{{- fail "ca.roots.configMap and ca.roots.secret are alternatives: set one" }}
{{- end }}
{{- if or $roots.configMap $roots.secret }}
{{- if not .Values.ca.existingSecret }}
{{- fail "ca.roots needs ca.existingSecret: roots only mean something to the CA in ca_dir" }}
{{- end }}
{{- default $roots.secret $roots.configMap }}
{{- else if .Values.ca.rootsDedicated }}
{{- fail "ca.rootsDedicated says the roots are dedicated to the trust domain, and ca.roots names none" }}
{{- end }}
{{- end }}

{{/* The issuer's settings file. */}}
{{- define "spiffex.settings" -}}
{{- $caRoots := include "spiffex.caRoots" . -}}
issuer: {{ include "spiffex.issuer" . | quote }}
trust_domain: {{ required "trustDomain is required" .Values.trustDomain | quote }}
keys_dir: /keys
token_ttl: {{ .Values.tokenTTL | quote }}
activation_delay: {{ .Values.activationDelay | quote }}
state:
  configmap:
    namespace: {{ .Release.Namespace | quote }}
    name: {{ include "spiffex.stateConfigMap" . | quote }}
{{- with .Values.x509SVIDTTL }}
x509_svid_ttl: {{ . | quote }}
{{- end }}
{{- if .Values.ca.existingSecret }}
ca_dir: /ca
{{- if $caRoots }}
ca_roots: {{ printf "/ca-roots/%s" .Values.ca.roots.key | quote }}
ca_roots_dedicated: {{ .Values.ca.rootsDedicated }}
{{- end }}
{{- end }}
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

{{/*
Chart name, truncated to the 63-character DNS label limit.
*/}}
{{- define "harnis.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Fully qualified app name. If the release name already contains the chart
name it is not repeated.
*/}}
{{- define "harnis.fullname" -}}
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

{{/*
Name of a sub-resource: <fullname>-<suffix>, within 63 characters.
Usage: include "harnis.componentName" (list . "migrate")
*/}}
{{- define "harnis.componentName" -}}
{{- $root := index . 0 }}
{{- $suffix := index . 1 }}
{{- printf "%s-%s" (include "harnis.fullname" $root | trunc (int (sub 62 (len $suffix)))) $suffix | trimSuffix "-" }}
{{- end }}

{{- define "harnis.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels.
*/}}
{{- define "harnis.labels" -}}
helm.sh/chart: {{ include "harnis.chart" . }}
{{ include "harnis.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: harnis
{{- end }}

{{/*
Selector labels for the API Pods. Kept minimal and stable: selectors are
immutable on Deployments.
*/}}
{{- define "harnis.selectorLabels" -}}
app.kubernetes.io/name: {{ include "harnis.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "harnis.apiSelectorLabels" -}}
{{ include "harnis.selectorLabels" . }}
app.kubernetes.io/component: api
{{- end }}

{{/*
Labels for a component other than the API (jobs, sandbox resources).
Usage: include "harnis.componentLabels" (list . "migrate")
*/}}
{{- define "harnis.componentLabels" -}}
{{- $root := index . 0 -}}
{{ include "harnis.labels" $root }}
app.kubernetes.io/component: {{ index . 1 }}
{{- end }}

{{- define "harnis.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "harnis.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Secret loaded into the API (envFrom).
*/}}
{{- define "harnis.secretName" -}}
{{- if .Values.secrets.existingSecret }}
{{- .Values.secrets.existingSecret }}
{{- else }}
{{- include "harnis.fullname" . }}
{{- end }}
{{- end }}

{{/*
Secret with the owner credentials for the migration and maintenance jobs.
*/}}
{{- define "harnis.migrationSecretName" -}}
{{- if .Values.secrets.existingMigrationSecret }}
{{- .Values.secrets.existingMigrationSecret }}
{{- else if .Values.secrets.existingSecret }}
{{- .Values.secrets.existingSecret }}
{{- else }}
{{- include "harnis.componentName" (list . "migration") }}
{{- end }}
{{- end }}

{{- define "harnis.configMapName" -}}
{{- include "harnis.fullname" . }}
{{- end }}

{{/*
Sandbox namespace, and whether it is dedicated (not the release namespace).
*/}}
{{- define "harnis.sandboxNamespace" -}}
{{- default .Release.Namespace .Values.sandbox.namespace.name }}
{{- end }}

{{- define "harnis.sandboxNamespaceDedicated" -}}
{{- if ne (include "harnis.sandboxNamespace" .) .Release.Namespace }}true{{- end }}
{{- end }}

{{/*
Image references. A digest takes precedence over the tag.
Usage: include "harnis.imageRef" (dict "image" .Values.image "root" .)
*/}}
{{- define "harnis.imageRef" -}}
{{- $tag := default .root.Chart.AppVersion .image.tag }}
{{- if .image.digest }}
{{- printf "%s@%s" .image.repository .image.digest }}
{{- else }}
{{- printf "%s:%s" .image.repository $tag }}
{{- end }}
{{- end }}

{{- define "harnis.image" -}}
{{- include "harnis.imageRef" (dict "image" .Values.image "root" .) }}
{{- end }}

{{- define "harnis.sandboxImage" -}}
{{- include "harnis.imageRef" (dict "image" .Values.sandbox.image "root" .) }}
{{- end }}

{{/*
Percent-encode a URL user-info component. urlquery encodes a space as "+",
which libpq would read literally, so turn it into %20 (a literal "+" has
already become %2B).
*/}}
{{- define "harnis.urlEscape" -}}
{{- . | toString | urlquery | replace "+" "%20" }}
{{- end }}

{{/*
DATABASE_URL (app role harnis_app) and MIGRATION_DATABASE_URL (owner).
Empty when nothing is configured, so NOTES.txt can warn about it.
*/}}
{{- define "harnis.databaseUrl" -}}
{{- $db := .Values.externalDatabase }}
{{- if $db.url }}
{{- $db.url }}
{{- else if $db.host }}
{{- printf "postgresql://harnis_app:%s@%s:%v/%s?sslmode=%s" (include "harnis.urlEscape" $db.appPassword) $db.host $db.port $db.database $db.sslmode }}
{{- end }}
{{- end }}

{{- define "harnis.migrationDatabaseUrl" -}}
{{- $db := .Values.externalDatabase }}
{{- if $db.migrationUrl }}
{{- $db.migrationUrl }}
{{- else if $db.host }}
{{- printf "postgresql://%s:%s@%s:%v/%s?sslmode=%s" (include "harnis.urlEscape" $db.ownerUser) (include "harnis.urlEscape" $db.ownerPassword) $db.host $db.port $db.database $db.sslmode }}
{{- end }}
{{- end }}

{{- define "harnis.redisUrl" -}}
{{- $r := .Values.externalRedis }}
{{- if $r.url }}
{{- $r.url }}
{{- else if $r.host }}
{{- $scheme := ternary "rediss" "redis" (eq (toString $r.tls) "true") }}
{{- if $r.password }}
{{- printf "%s://:%s@%s:%v/%v" $scheme (include "harnis.urlEscape" $r.password) $r.host $r.port $r.db }}
{{- else }}
{{- printf "%s://%s:%v/%v" $scheme $r.host $r.port $r.db }}
{{- end }}
{{- end }}
{{- end }}

{{/*
JWT secret: the value from values, else the one already stored in the
release's Secret (kept across upgrades), else a new random one.
*/}}
{{- define "harnis.jwtSecret" -}}
{{- if .Values.secrets.jwtSecret }}
{{- .Values.secrets.jwtSecret }}
{{- else }}
{{- $existing := lookup "v1" "Secret" .Release.Namespace (include "harnis.fullname" .) }}
{{- if and $existing $existing.data (hasKey $existing.data "JWT_SECRET") }}
{{- index $existing.data "JWT_SECRET" | b64dec }}
{{- else }}
{{- randAlphaNum 64 }}
{{- end }}
{{- end }}
{{- end }}

{{- define "harnis.metricsToken" -}}
{{- if .Values.metrics.token }}
{{- .Values.metrics.token }}
{{- else }}
{{- $existing := lookup "v1" "Secret" .Release.Namespace (include "harnis.fullname" .) }}
{{- if and $existing $existing.data (hasKey $existing.data "METRICS_TOKEN") }}
{{- index $existing.data "METRICS_TOKEN" | b64dec }}
{{- else }}
{{- randAlphaNum 48 }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Pod spec fragments shared by the jobs.
*/}}
{{- define "harnis.jobPodSecurity" -}}
securityContext:
  {{- toYaml .Values.api.podSecurityContext | nindent 2 }}
{{- with .Values.imagePullSecrets }}
imagePullSecrets:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .Values.jobs.nodeSelector }}
nodeSelector:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .Values.jobs.tolerations }}
tolerations:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- with .Values.jobs.affinity }}
affinity:
  {{- toYaml . | nindent 2 }}
{{- end }}
{{- end }}

{{- define "harnis.jobVolumes" -}}
volumes:
  - name: tmp
    emptyDir:
      medium: Memory
      sizeLimit: 32Mi
{{- end }}

{{- define "harnis.jobVolumeMounts" -}}
volumeMounts:
  - name: tmp
    mountPath: /tmp
{{- end }}

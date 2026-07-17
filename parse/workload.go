package parse

// workload.go exposes structural workload extraction from IaC files:
// Kubernetes manifests (including CRDs that embed pod templates),
// docker-compose files and Dockerfiles. Unlike the package parsers in
// local.go/local_extra.go, these return the full container shape —
// image, env, args, command, volume mounts, volumes, annotations and
// resource keys — so callers (AI-BOM infrastructure detection, container
// analysis) can reason about what the IaC would run, not just which
// packages it installs.
//
// The same leniency contract applies: malformed documents are skipped,
// never returned as errors, and no function panics on unexpected shapes.

import (
	"bytes"
	"encoding/json"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// ---------------------------------------------------------------------------
// Image references
// ---------------------------------------------------------------------------

// ImageRef is a parsed container image reference with the tag and digest
// held separately so a digest is never mistaken for a version.
type ImageRef struct {
	Raw    string // the reference as written
	Name   string // repository (registry included when present)
	Tag    string // tag portion, empty when none
	Digest string // digest portion (e.g. "sha256:..."), empty when none
}

var imageDigestRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// DigestValid reports whether the digest is present and well-formed.
func (r ImageRef) DigestValid() bool {
	return imageDigestRe.MatchString(r.Digest)
}

// SplitImageRef parses an image reference into name, tag and digest parts.
// It performs no validation beyond splitting; use DigestValid for the
// digest well-formedness check.
func SplitImageRef(ref string) ImageRef {
	out := ImageRef{Raw: strings.TrimSpace(ref)}
	rest := out.Raw
	if idx := strings.Index(rest, "@"); idx > 0 {
		out.Digest = rest[idx+1:]
		rest = rest[:idx]
	}
	lastSlash := strings.LastIndex(rest, "/")
	lastColon := strings.LastIndex(rest, ":")
	if lastColon > lastSlash {
		out.Tag = rest[lastColon+1:]
		rest = rest[:lastColon]
	}
	out.Name = rest
	return out
}

// ImagePlaceholder reports whether an image reference is a build-time or
// template placeholder ($VAR, ${VAR}, Go/Helm {{ ... }}) rather than a
// concrete reference. Callers should drop such references instead of
// reporting them.
func ImagePlaceholder(ref string) bool {
	ref = strings.TrimSpace(ref)
	return ref == "" || ref == "scratch" ||
		strings.HasPrefix(ref, "$") ||
		strings.Contains(ref, "{{") || strings.Contains(ref, "}}")
}

// ---------------------------------------------------------------------------
// Workload model
// ---------------------------------------------------------------------------

// WorkloadEnvVar is a single environment entry on a container. When the
// value comes from a reference (valueFrom / secretKeyRef / configMapKeyRef
// / env_file) IsRef is true and Value is empty — reference targets are
// deliberately never resolved.
type WorkloadEnvVar struct {
	Name  string
	Value string
	IsRef bool
}

// WorkloadMount is a container volume mount.
type WorkloadMount struct {
	Name      string // volume name it refers to
	MountPath string
	ReadOnly  bool
}

// WorkloadVolume is a pod-level volume with its backing source classified.
type WorkloadVolume struct {
	Name       string
	Source     string // pvc | configMap | secret | hostPath | emptyDir | nfs | csi | image | unknown
	SourceName string // claim name, config map name, host path, nfs server:path, csi driver...
}

// WorkloadContainer is one container within a workload.
type WorkloadContainer struct {
	Name         string
	Image        string
	Init         bool
	Env          []WorkloadEnvVar
	Command      []string
	Args         []string
	Mounts       []WorkloadMount
	ResourceKeys []string // keys of resources.limits + resources.requests (e.g. nvidia.com/gpu)
}

// Workload is a normalized deployable unit extracted from an IaC file:
// one Kubernetes workload document, one compose service, or one Dockerfile.
type Workload struct {
	// Kind is the Kubernetes kind, "compose-service" or "dockerfile".
	Kind       string
	APIVersion string // Kubernetes only
	Name       string // metadata.name / service name / file basename
	// Annotations merges workload metadata.annotations with the pod
	// template's annotations (template keys win on conflict).
	Annotations map[string]string
	Containers  []WorkloadContainer
	Volumes     []WorkloadVolume
	// NodeSelector holds the pod template's nodeSelector map (Kubernetes only).
	NodeSelector map[string]string
	SourceFile   string
	// DocIndex is the zero-based document index in a multi-doc YAML stream.
	DocIndex int
	// Raw is the decoded document for callers that need fields outside the
	// normalized shape (CRD-specific paths). Nil for compose/Dockerfile.
	Raw map[string]any
}

// LookupVolume resolves a mount's volume name against the workload volumes.
func (w *Workload) LookupVolume(name string) (WorkloadVolume, bool) {
	for _, v := range w.Volumes {
		if v.Name == name {
			return v, true
		}
	}
	return WorkloadVolume{}, false
}

// ---------------------------------------------------------------------------
// Typed map accessors — every traversal is nil-safe and ok-checked.
// ---------------------------------------------------------------------------

func mapAt(m map[string]any, key string) map[string]any {
	if m == nil {
		return nil
	}
	child, _ := m[key].(map[string]any)
	return child
}

func sliceAt(m map[string]any, key string) []any {
	if m == nil {
		return nil
	}
	child, _ := m[key].([]any)
	return child
}

func stringAt(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	s, _ := m[key].(string)
	return s
}

func boolAt(m map[string]any, key string) bool {
	if m == nil {
		return false
	}
	b, _ := m[key].(bool)
	return b
}

func stringMapAt(m map[string]any, key string) map[string]string {
	child := mapAt(m, key)
	if len(child) == 0 {
		return nil
	}
	out := make(map[string]string, len(child))
	for k, v := range child {
		if s, ok := v.(string); ok {
			out[k] = s
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// stringsAt returns a []string from either a YAML list of scalars or a
// single scalar value.
func stringsAt(m map[string]any, key string) []string {
	if m == nil {
		return nil
	}
	switch v := m[key].(type) {
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case string:
		return []string{v}
	}
	return nil
}

// FieldAt walks a dot-separated path through nested maps and returns the
// string value at the leaf. ok is false when any step is missing or the
// leaf is not a string.
func FieldAt(m map[string]any, dotPath string) (string, bool) {
	if m == nil || dotPath == "" {
		return "", false
	}
	parts := strings.Split(dotPath, ".")
	cur := m
	for i, part := range parts {
		if i == len(parts)-1 {
			s, ok := cur[part].(string)
			return s, ok
		}
		cur = mapAt(cur, part)
		if cur == nil {
			return "", false
		}
	}
	return "", false
}

// ---------------------------------------------------------------------------
// Kubernetes
// ---------------------------------------------------------------------------

// maxPodSpecSearchDepth bounds the recursive pod-template discovery inside
// CRDs so a pathological document cannot cause unbounded work.
const maxPodSpecSearchDepth = 12

// ParseKubernetesWorkloads extracts workloads from a (possibly multi-doc)
// Kubernetes YAML stream. Documents that fail to decode, or that lack
// apiVersion/kind, are skipped. For kinds that are not core workload kinds
// (CRDs such as InferenceService, PyTorchJob, RayJob, Argo Workflow) any
// pod specs embedded anywhere in the document are discovered by a bounded
// recursive walk, so operator-managed workloads are not invisible.
func ParseKubernetesWorkloads(data []byte, filePath string) []Workload {
	var out []Workload
	// Split the stream on document separators and decode each document
	// independently: yaml.Decoder cannot recover after a malformed document
	// (it returns the same error forever), while per-document decoding lets
	// valid documents on either side of a broken one still be scanned.
	for docIndex, docBytes := range splitYAMLDocuments(data) {
		var doc map[string]any
		if err := yaml.Unmarshal(docBytes, &doc); err != nil {
			continue // malformed document: skip it, keep the rest
		}
		apiVersion := stringAt(doc, "apiVersion")
		kind := stringAt(doc, "kind")
		if apiVersion == "" || kind == "" {
			continue
		}
		meta := mapAt(doc, "metadata")
		w := Workload{
			Kind:        kind,
			APIVersion:  apiVersion,
			Name:        stringAt(meta, "name"),
			Annotations: stringMapAt(meta, "annotations"),
			SourceFile:  filePath,
			DocIndex:    docIndex,
			Raw:         doc,
		}
		for _, podSpec := range findPodSpecs(doc, kind) {
			mergePodSpec(&w, podSpec)
		}
		out = append(out, w)
	}
	return out
}

// splitYAMLDocuments splits a YAML stream on `---` document separators
// (a separator is only recognized at the start of a line).
func splitYAMLDocuments(data []byte) [][]byte {
	lines := bytes.Split(data, []byte("\n"))
	var docs [][]byte
	var current [][]byte
	flush := func() {
		if len(current) == 0 {
			return
		}
		doc := bytes.Join(current, []byte("\n"))
		if len(bytes.TrimSpace(doc)) > 0 {
			docs = append(docs, doc)
		}
		current = nil
	}
	for _, line := range lines {
		trimmed := bytes.TrimRight(line, " \t\r")
		if string(trimmed) == "---" || bytes.HasPrefix(trimmed, []byte("--- ")) {
			flush()
			continue
		}
		current = append(current, line)
	}
	flush()
	return docs
}

// findPodSpecs locates every pod spec in a document. Core workload kinds
// use their well-known paths; anything else falls back to a bounded
// recursive search for maps that look like pod specs.
func findPodSpecs(doc map[string]any, kind string) []map[string]any {
	spec := mapAt(doc, "spec")
	switch kind {
	case "Pod":
		if spec != nil {
			return []map[string]any{spec}
		}
	case "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "ReplicationController":
		if ps := mapAt(mapAt(spec, "template"), "spec"); ps != nil {
			return []map[string]any{ps}
		}
	case "CronJob":
		if ps := mapAt(mapAt(mapAt(mapAt(spec, "jobTemplate"), "spec"), "template"), "spec"); ps != nil {
			return []map[string]any{ps}
		}
	}
	// CRD or unexpected shape: search for embedded pod specs.
	var found []map[string]any
	searchPodSpecs(spec, 0, &found)
	return found
}

// looksLikePodSpec requires a containers list whose first entry carries an
// image or name — the discriminator that separates real pod specs from
// coincidental "containers" keys.
func looksLikePodSpec(m map[string]any) bool {
	containers := sliceAt(m, "containers")
	if len(containers) == 0 {
		return false
	}
	first, ok := containers[0].(map[string]any)
	if !ok {
		return false
	}
	return stringAt(first, "image") != "" || stringAt(first, "name") != ""
}

func searchPodSpecs(node any, depth int, found *[]map[string]any) {
	if depth > maxPodSpecSearchDepth || len(*found) >= 16 {
		return
	}
	switch v := node.(type) {
	case map[string]any:
		if looksLikePodSpec(v) {
			*found = append(*found, v)
			return // do not descend into a found pod spec
		}
		for _, child := range v {
			searchPodSpecs(child, depth+1, found)
		}
	case []any:
		for _, child := range v {
			searchPodSpecs(child, depth+1, found)
		}
	}
}

// mergePodSpec appends a pod spec's containers, volumes, nodeSelector and
// template annotations onto the workload.
func mergePodSpec(w *Workload, podSpec map[string]any) {
	for _, c := range parseContainers(sliceAt(podSpec, "containers"), false) {
		w.Containers = append(w.Containers, c)
	}
	for _, c := range parseContainers(sliceAt(podSpec, "initContainers"), true) {
		w.Containers = append(w.Containers, c)
	}
	for _, c := range parseContainers(sliceAt(podSpec, "ephemeralContainers"), false) {
		w.Containers = append(w.Containers, c)
	}
	for _, raw := range sliceAt(podSpec, "volumes") {
		vol, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		w.Volumes = append(w.Volumes, classifyVolume(vol))
	}
	if sel := stringMapAt(podSpec, "nodeSelector"); sel != nil {
		if w.NodeSelector == nil {
			w.NodeSelector = map[string]string{}
		}
		for k, v := range sel {
			w.NodeSelector[k] = v
		}
	}
}

func parseContainers(list []any, init bool) []WorkloadContainer {
	var out []WorkloadContainer
	for _, raw := range list {
		c, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		wc := WorkloadContainer{
			Name:    stringAt(c, "name"),
			Image:   stringAt(c, "image"),
			Init:    init,
			Command: stringsAt(c, "command"),
			Args:    stringsAt(c, "args"),
		}
		for _, rawEnv := range sliceAt(c, "env") {
			env, ok := rawEnv.(map[string]any)
			if !ok {
				continue
			}
			name := stringAt(env, "name")
			if name == "" {
				continue
			}
			_, hasRef := env["valueFrom"]
			entry := WorkloadEnvVar{Name: name, IsRef: hasRef}
			if !hasRef {
				entry.Value = stringAt(env, "value")
			}
			wc.Env = append(wc.Env, entry)
		}
		for _, rawMount := range sliceAt(c, "volumeMounts") {
			mount, ok := rawMount.(map[string]any)
			if !ok {
				continue
			}
			wc.Mounts = append(wc.Mounts, WorkloadMount{
				Name:      stringAt(mount, "name"),
				MountPath: stringAt(mount, "mountPath"),
				ReadOnly:  boolAt(mount, "readOnly"),
			})
		}
		resources := mapAt(c, "resources")
		for _, section := range []string{"limits", "requests"} {
			for key := range mapAt(resources, section) {
				if !containsString(wc.ResourceKeys, key) {
					wc.ResourceKeys = append(wc.ResourceKeys, key)
				}
			}
		}
		out = append(out, wc)
	}
	return out
}

func containsString(list []string, s string) bool {
	for _, item := range list {
		if item == s {
			return true
		}
	}
	return false
}

// classifyVolume maps a Kubernetes volume entry to its backing source.
func classifyVolume(vol map[string]any) WorkloadVolume {
	out := WorkloadVolume{Name: stringAt(vol, "name"), Source: "unknown"}
	if pvc := mapAt(vol, "persistentVolumeClaim"); pvc != nil {
		out.Source, out.SourceName = "pvc", stringAt(pvc, "claimName")
	} else if cm := mapAt(vol, "configMap"); cm != nil {
		out.Source, out.SourceName = "configMap", stringAt(cm, "name")
	} else if sec := mapAt(vol, "secret"); sec != nil {
		out.Source, out.SourceName = "secret", stringAt(sec, "secretName")
	} else if hp := mapAt(vol, "hostPath"); hp != nil {
		out.Source, out.SourceName = "hostPath", stringAt(hp, "path")
	} else if _, ok := vol["emptyDir"]; ok {
		out.Source = "emptyDir"
	} else if nfs := mapAt(vol, "nfs"); nfs != nil {
		out.Source = "nfs"
		out.SourceName = strings.TrimSuffix(stringAt(nfs, "server")+":"+stringAt(nfs, "path"), ":")
	} else if csi := mapAt(vol, "csi"); csi != nil {
		out.Source, out.SourceName = "csi", stringAt(csi, "driver")
	} else if img := mapAt(vol, "image"); img != nil {
		out.Source, out.SourceName = "image", stringAt(img, "reference")
	}
	return out
}

// ---------------------------------------------------------------------------
// docker-compose
// ---------------------------------------------------------------------------

// ParseComposeWorkloads extracts one workload per compose service. Both the
// map and list forms of `environment` are handled; `env_file` entries are
// recorded as reference-only (IsRef) markers.
func ParseComposeWorkloads(data []byte, filePath string) []Workload {
	var doc map[string]any
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil
	}
	services := mapAt(doc, "services")
	if services == nil {
		return nil
	}
	var out []Workload
	for name, raw := range services {
		svc, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		// Compose `entrypoint` corresponds to a Kubernetes container
		// `command`, and compose `command` to `args`.
		wc := WorkloadContainer{
			Name:    name,
			Image:   stringAt(svc, "image"),
			Command: stringsAt(svc, "entrypoint"),
			Args:    stringsAt(svc, "command"),
		}
		wc.Env = parseComposeEnvironment(svc)
		w := Workload{
			Kind:       "compose-service",
			Name:       name,
			Containers: []WorkloadContainer{wc},
			SourceFile: filePath,
		}
		for _, volRaw := range sliceAt(svc, "volumes") {
			volStr, ok := volRaw.(string)
			if !ok {
				continue
			}
			parts := strings.Split(volStr, ":")
			if len(parts) >= 2 {
				w.Volumes = append(w.Volumes, WorkloadVolume{Name: parts[0], Source: "bind", SourceName: parts[0]})
				w.Containers[0].Mounts = append(w.Containers[0].Mounts, WorkloadMount{Name: parts[0], MountPath: parts[1]})
			}
		}
		out = append(out, w)
	}
	return out
}

func parseComposeEnvironment(svc map[string]any) []WorkloadEnvVar {
	var out []WorkloadEnvVar
	switch env := svc["environment"].(type) {
	case map[string]any:
		for k, v := range env {
			entry := WorkloadEnvVar{Name: k}
			if s, ok := v.(string); ok {
				entry.Value = s
			}
			out = append(out, entry)
		}
	case []any:
		for _, item := range env {
			s, ok := item.(string)
			if !ok {
				continue
			}
			if idx := strings.Index(s, "="); idx > 0 {
				out = append(out, WorkloadEnvVar{Name: s[:idx], Value: s[idx+1:]})
			} else if s != "" {
				// Bare name: value inherited from the host at runtime.
				out = append(out, WorkloadEnvVar{Name: s, IsRef: true})
			}
		}
	}
	if files := stringsAt(svc, "env_file"); len(files) > 0 {
		for _, f := range files {
			out = append(out, WorkloadEnvVar{Name: "env_file:" + f, IsRef: true})
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Dockerfile
// ---------------------------------------------------------------------------

// ParseDockerfileWorkload extracts a single workload from a Dockerfile:
// one container per FROM stage image (stage aliases referenced by later
// FROM lines are skipped — they are internal, not pulled images), with the
// final stage carrying ENV / CMD / ENTRYPOINT.
func ParseDockerfileWorkload(data []byte, filePath string) *Workload {
	instructions := dockerfileInstructions(string(data))
	if len(instructions) == 0 {
		return nil
	}
	w := &Workload{Kind: "dockerfile", Name: filePath, SourceFile: filePath}
	aliases := map[string]bool{}
	var current *WorkloadContainer
	for _, instruction := range instructions {
		upper := strings.ToUpper(instruction)
		switch {
		case strings.HasPrefix(upper, "FROM "):
			fields := strings.Fields(strings.TrimSpace(instruction[5:]))
			for len(fields) > 0 && strings.HasPrefix(fields[0], "--") {
				fields = fields[1:]
			}
			if len(fields) == 0 {
				continue
			}
			image := fields[0]
			// Record "FROM x AS alias" aliases so later "FROM alias"
			// lines are not misread as registry images.
			if len(fields) >= 3 && strings.EqualFold(fields[1], "AS") {
				aliases[strings.ToLower(fields[2])] = true
			}
			if aliases[strings.ToLower(image)] {
				continue
			}
			w.Containers = append(w.Containers, WorkloadContainer{
				Name:  "stage-" + image,
				Image: image,
			})
			current = &w.Containers[len(w.Containers)-1]
		case strings.HasPrefix(upper, "ENV "):
			if current == nil {
				continue
			}
			current.Env = append(current.Env, parseDockerfileEnv(strings.TrimSpace(instruction[4:]))...)
		case strings.HasPrefix(upper, "CMD "), strings.HasPrefix(upper, "ENTRYPOINT "):
			if current == nil {
				continue
			}
			body := strings.TrimSpace(instruction[strings.Index(instruction, " ")+1:])
			args := parseDockerfileExecForm(body)
			if strings.HasPrefix(upper, "CMD ") {
				current.Args = append(current.Args, args...)
			} else {
				current.Command = append(current.Command, args...)
			}
		}
	}
	if len(w.Containers) == 0 {
		return nil
	}
	return w
}

// parseDockerfileEnv handles both `ENV K=V K2=V2` and the legacy
// `ENV K V` single-pair form.
func parseDockerfileEnv(body string) []WorkloadEnvVar {
	var out []WorkloadEnvVar
	if strings.Contains(body, "=") {
		for _, tok := range shellishFields(body) {
			idx := strings.Index(tok, "=")
			if idx <= 0 {
				continue
			}
			out = append(out, WorkloadEnvVar{
				Name:  tok[:idx],
				Value: strings.Trim(tok[idx+1:], `"'`),
			})
		}
		return out
	}
	fields := strings.Fields(body)
	if len(fields) >= 2 {
		out = append(out, WorkloadEnvVar{
			Name:  fields[0],
			Value: strings.Trim(strings.Join(fields[1:], " "), `"'`),
		})
	}
	return out
}

// parseDockerfileExecForm parses a CMD/ENTRYPOINT body: JSON exec-array
// form when it starts with '[', shell form otherwise.
func parseDockerfileExecForm(body string) []string {
	if strings.HasPrefix(body, "[") {
		var arr []string
		if err := json.Unmarshal([]byte(body), &arr); err == nil {
			return arr
		}
		// Fall through to shell tokenization on malformed JSON.
	}
	return shellishFields(body)
}

package parse

import (
	"strings"
	"testing"
)

func TestSplitImageRef(t *testing.T) {
	cases := []struct {
		ref, name, tag, digest string
		digestValid            bool
	}{
		{"vllm/vllm-openai:v0.6.3", "vllm/vllm-openai", "v0.6.3", "", false},
		{"nvcr.io/nvidia/tritonserver:24.05-py3", "nvcr.io/nvidia/tritonserver", "24.05-py3", "", false},
		{"ollama/ollama", "ollama/ollama", "", "", false},
		{"registry:5000/repo/app:1.0", "registry:5000/repo/app", "1.0", "", false},
		{
			"ghcr.io/org/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			"ghcr.io/org/app", "",
			"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", true,
		},
		{"ghcr.io/org/app:v1@sha256:zzz", "ghcr.io/org/app", "v1", "sha256:zzz", false},
	}
	for _, tc := range cases {
		got := SplitImageRef(tc.ref)
		if got.Name != tc.name || got.Tag != tc.tag || got.Digest != tc.digest {
			t.Errorf("SplitImageRef(%q) = %+v, want name=%q tag=%q digest=%q", tc.ref, got, tc.name, tc.tag, tc.digest)
		}
		if got.DigestValid() != tc.digestValid {
			t.Errorf("SplitImageRef(%q).DigestValid() = %v, want %v", tc.ref, got.DigestValid(), tc.digestValid)
		}
	}
}

func TestImagePlaceholder(t *testing.T) {
	for _, bad := range []string{"", "scratch", "$IMAGE", "${IMAGE}", "{{ .Values.image }}", "repo/{{ .Values.tag }}"} {
		if !ImagePlaceholder(bad) {
			t.Errorf("ImagePlaceholder(%q) = false, want true", bad)
		}
	}
	if ImagePlaceholder("vllm/vllm-openai:v0.6.3") {
		t.Error("concrete ref flagged as placeholder")
	}
}

const deploymentYAML = `
apiVersion: apps/v1
kind: Deployment
metadata:
  name: llm-server
  annotations:
    vulnetix.com/model.primary: meta-llama/Llama-3.1-8B-Instruct
spec:
  template:
    spec:
      nodeSelector:
        cloud.google.com/gke-accelerator: nvidia-l4
      containers:
        - name: server
          image: vllm/vllm-openai:v0.6.3
          args: ["--model", "meta-llama/Llama-3.1-8B-Instruct", "--port=8000"]
          env:
            - name: HF_MODEL_ID
              value: meta-llama/Llama-3.1-8B-Instruct
            - name: HF_TOKEN
              valueFrom:
                secretKeyRef:
                  name: hf-secret
                  key: token
          resources:
            limits:
              nvidia.com/gpu: "1"
          volumeMounts:
            - name: model-cache
              mountPath: /models
              readOnly: true
      initContainers:
        - name: fetch
          image: busybox:1.36
      volumes:
        - name: model-cache
          persistentVolumeClaim:
            claimName: models-pvc
`

func TestParseKubernetesWorkloadsDeployment(t *testing.T) {
	ws := ParseKubernetesWorkloads([]byte(deploymentYAML), "deploy.yaml")
	if len(ws) != 1 {
		t.Fatalf("got %d workloads, want 1", len(ws))
	}
	w := ws[0]
	if w.Kind != "Deployment" || w.Name != "llm-server" {
		t.Fatalf("unexpected workload identity: %+v", w)
	}
	if w.Annotations["vulnetix.com/model.primary"] != "meta-llama/Llama-3.1-8B-Instruct" {
		t.Error("annotation missing")
	}
	if len(w.Containers) != 2 {
		t.Fatalf("got %d containers, want 2", len(w.Containers))
	}
	var main *WorkloadContainer
	for i := range w.Containers {
		if w.Containers[i].Name == "server" {
			main = &w.Containers[i]
		}
		if w.Containers[i].Name == "fetch" && !w.Containers[i].Init {
			t.Error("init container not marked Init")
		}
	}
	if main == nil {
		t.Fatal("main container not found")
	}
	if main.Image != "vllm/vllm-openai:v0.6.3" {
		t.Errorf("image = %q", main.Image)
	}
	if len(main.Args) != 3 || main.Args[0] != "--model" {
		t.Errorf("args = %v", main.Args)
	}
	var hfModel, hfToken *WorkloadEnvVar
	for i := range main.Env {
		switch main.Env[i].Name {
		case "HF_MODEL_ID":
			hfModel = &main.Env[i]
		case "HF_TOKEN":
			hfToken = &main.Env[i]
		}
	}
	if hfModel == nil || hfModel.Value != "meta-llama/Llama-3.1-8B-Instruct" || hfModel.IsRef {
		t.Errorf("HF_MODEL_ID = %+v", hfModel)
	}
	if hfToken == nil || !hfToken.IsRef || hfToken.Value != "" {
		t.Errorf("HF_TOKEN ref not honored: %+v", hfToken)
	}
	if len(main.ResourceKeys) != 1 || main.ResourceKeys[0] != "nvidia.com/gpu" {
		t.Errorf("resource keys = %v", main.ResourceKeys)
	}
	if len(main.Mounts) != 1 || main.Mounts[0].MountPath != "/models" || !main.Mounts[0].ReadOnly {
		t.Errorf("mounts = %+v", main.Mounts)
	}
	vol, ok := w.LookupVolume("model-cache")
	if !ok || vol.Source != "pvc" || vol.SourceName != "models-pvc" {
		t.Errorf("volume = %+v ok=%v", vol, ok)
	}
	if w.NodeSelector["cloud.google.com/gke-accelerator"] != "nvidia-l4" {
		t.Errorf("nodeSelector = %v", w.NodeSelector)
	}
}

func TestClassifyVolume(t *testing.T) {
	cases := []struct {
		name       string
		vol        map[string]any
		source     string
		sourceName string
	}{
		{
			name:       "persistentVolumeClaim",
			vol:        map[string]any{"name": "cache", "persistentVolumeClaim": map[string]any{"claimName": "models-pvc"}},
			source:     "pvc",
			sourceName: "models-pvc",
		},
		{
			name:       "configMap",
			vol:        map[string]any{"name": "cfg", "configMap": map[string]any{"name": "app-config"}},
			source:     "configMap",
			sourceName: "app-config",
		},
		{
			name:       "secret",
			vol:        map[string]any{"name": "sec", "secret": map[string]any{"secretName": "hf-secret"}},
			source:     "secret",
			sourceName: "hf-secret",
		},
		{
			name:       "hostPath",
			vol:        map[string]any{"name": "host", "hostPath": map[string]any{"path": "/data"}},
			source:     "hostPath",
			sourceName: "/data",
		},
		{
			name:   "emptyDir",
			vol:    map[string]any{"name": "tmp", "emptyDir": map[string]any{}},
			source: "emptyDir",
		},
		{
			name:       "nfs",
			vol:        map[string]any{"name": "nfs", "nfs": map[string]any{"server": "nfs.example.com", "path": "/data"}},
			source:     "nfs",
			sourceName: "nfs.example.com:/data",
		},
		{
			name:       "nfs empty path",
			vol:        map[string]any{"name": "nfs", "nfs": map[string]any{"server": "nfs.example.com"}},
			source:     "nfs",
			sourceName: "nfs.example.com",
		},
		{
			name:       "csi",
			vol:        map[string]any{"name": "csi", "csi": map[string]any{"driver": "secrets.example.com"}},
			source:     "csi",
			sourceName: "secrets.example.com",
		},
		{
			name:       "image",
			vol:        map[string]any{"name": "img", "image": map[string]any{"reference": "busybox:1.36"}},
			source:     "image",
			sourceName: "busybox:1.36",
		},
		{
			name:   "unknown",
			vol:    map[string]any{"name": "mystery"},
			source: "unknown",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := classifyVolume(tc.vol)
			if got.Source != tc.source || got.SourceName != tc.sourceName {
				t.Errorf("classifyVolume(%v) = Source %q, SourceName %q; want %q, %q",
					tc.vol, got.Source, got.SourceName, tc.source, tc.sourceName)
			}
		})
	}
}

const crdYAML = `
apiVersion: kubeflow.org/v1
kind: PyTorchJob
metadata:
  name: train
spec:
  pytorchReplicaSpecs:
    Master:
      replicas: 1
      template:
        spec:
          containers:
            - name: pytorch
              image: pytorch/pytorch:2.4.0-cuda12.1-cudnn9-runtime
    Worker:
      replicas: 2
      template:
        spec:
          containers:
            - name: pytorch
              image: pytorch/pytorch:2.4.0-cuda12.1-cudnn9-runtime
---
apiVersion: serving.kserve.io/v1beta1
kind: InferenceService
metadata:
  name: sklearn-iris
spec:
  predictor:
    model:
      modelFormat:
        name: sklearn
      storageUri: gs://kfserving-examples/models/sklearn/1.0/model
`

func TestParseKubernetesWorkloadsCRD(t *testing.T) {
	ws := ParseKubernetesWorkloads([]byte(crdYAML), "crd.yaml")
	if len(ws) != 2 {
		t.Fatalf("got %d workloads, want 2", len(ws))
	}
	pt := ws[0]
	if pt.Kind != "PyTorchJob" {
		t.Fatalf("kind = %q", pt.Kind)
	}
	if len(pt.Containers) != 2 {
		t.Errorf("PyTorchJob containers = %d, want 2 (master+worker)", len(pt.Containers))
	}
	for _, c := range pt.Containers {
		if !strings.HasPrefix(c.Image, "pytorch/pytorch:") {
			t.Errorf("unexpected image %q", c.Image)
		}
	}
	isvc := ws[1]
	if isvc.Kind != "InferenceService" {
		t.Fatalf("kind = %q", isvc.Kind)
	}
	if got, ok := FieldAt(isvc.Raw, "spec.predictor.model.storageUri"); !ok || got != "gs://kfserving-examples/models/sklearn/1.0/model" {
		t.Errorf("FieldAt storageUri = %q ok=%v", got, ok)
	}
	if got, ok := FieldAt(isvc.Raw, "spec.predictor.model.modelFormat.name"); !ok || got != "sklearn" {
		t.Errorf("FieldAt modelFormat = %q ok=%v", got, ok)
	}
	if _, ok := FieldAt(isvc.Raw, "spec.predictor.model.missing"); ok {
		t.Error("FieldAt on missing path returned ok")
	}
}

func TestParseKubernetesWorkloadsMalformedDocSkipped(t *testing.T) {
	stream := "apiVersion: v1\nkind: Pod\nmetadata: {name: ok}\nspec:\n  containers:\n    - name: c\n      image: ollama/ollama:0.3.12\n---\n\t badyaml: [unclosed\n---\napiVersion: v1\nkind: Service\nmetadata: {name: svc}\n"
	ws := ParseKubernetesWorkloads([]byte(stream), "mixed.yaml")
	if len(ws) < 1 {
		t.Fatal("valid docs lost when a malformed doc is present")
	}
	if ws[0].Kind != "Pod" || len(ws[0].Containers) != 1 {
		t.Errorf("pod not extracted: %+v", ws[0])
	}
}

func TestParseKubernetesWorkloadsNonK8s(t *testing.T) {
	gha := "name: CI\non: push\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n"
	if ws := ParseKubernetesWorkloads([]byte(gha), "ci.yml"); len(ws) != 0 {
		t.Errorf("GitHub Actions YAML produced %d workloads, want 0", len(ws))
	}
}

const composeYAML = `
services:
  llm:
    image: ollama/ollama:0.3.12
    entrypoint: ["/bin/ollama"]
    command: ["serve"]
    environment:
      OLLAMA_HOST: 0.0.0.0
    volumes:
      - ollama-models:/models
  agent:
    image: langflowai/langflow:1.0.19
    environment:
      - OPENAI_API_KEY
      - LANGCHAIN_TRACING_V2=true
    env_file:
      - .env
`

func TestParseComposeWorkloads(t *testing.T) {
	ws := ParseComposeWorkloads([]byte(composeYAML), "docker-compose.yml")
	if len(ws) != 2 {
		t.Fatalf("got %d workloads, want 2", len(ws))
	}
	byName := map[string]Workload{}
	for _, w := range ws {
		byName[w.Name] = w
	}
	llm := byName["llm"]
	if llm.Containers[0].Image != "ollama/ollama:0.3.12" {
		t.Errorf("image = %q", llm.Containers[0].Image)
	}
	if got := llm.Containers[0].Command; len(got) != 1 || got[0] != "/bin/ollama" {
		t.Errorf("command (entrypoint) = %v", got)
	}
	if got := llm.Containers[0].Args; len(got) != 1 || got[0] != "serve" {
		t.Errorf("args (compose command) = %v", got)
	}
	if len(llm.Containers[0].Mounts) != 1 || llm.Containers[0].Mounts[0].MountPath != "/models" {
		t.Errorf("mounts = %+v", llm.Containers[0].Mounts)
	}
	agent := byName["agent"]
	var sawBareRef, sawKV, sawEnvFile bool
	for _, e := range agent.Containers[0].Env {
		switch {
		case e.Name == "OPENAI_API_KEY" && e.IsRef && e.Value == "":
			sawBareRef = true
		case e.Name == "LANGCHAIN_TRACING_V2" && e.Value == "true":
			sawKV = true
		case strings.HasPrefix(e.Name, "env_file:") && e.IsRef:
			sawEnvFile = true
		}
	}
	if !sawBareRef || !sawKV || !sawEnvFile {
		t.Errorf("compose env forms not all parsed: bare=%v kv=%v envfile=%v (%+v)",
			sawBareRef, sawKV, sawEnvFile, agent.Containers[0].Env)
	}
}

const dockerfileText = `
FROM python:3.12 AS builder
RUN pip install build

FROM ghcr.io/huggingface/text-embeddings-inference:1.5
ENV MODEL_NAME=BAAI/bge-large-en-v1.5 PORT=8080
ENV LEGACY_FORM legacy value
ENTRYPOINT ["text-embeddings-router"]
CMD ["--model-id", "BAAI/bge-large-en-v1.5"]

FROM builder
`

func TestParseDockerfileWorkload(t *testing.T) {
	w := ParseDockerfileWorkload([]byte(dockerfileText), "Dockerfile")
	if w == nil {
		t.Fatal("nil workload")
	}
	if len(w.Containers) != 2 {
		t.Fatalf("got %d containers, want 2 (alias FROM skipped)", len(w.Containers))
	}
	tei := w.Containers[1]
	if tei.Image != "ghcr.io/huggingface/text-embeddings-inference:1.5" {
		t.Errorf("image = %q", tei.Image)
	}
	envByName := map[string]string{}
	for _, e := range tei.Env {
		envByName[e.Name] = e.Value
	}
	if envByName["MODEL_NAME"] != "BAAI/bge-large-en-v1.5" {
		t.Errorf("MODEL_NAME = %q", envByName["MODEL_NAME"])
	}
	if envByName["LEGACY_FORM"] != "legacy value" {
		t.Errorf("legacy ENV form = %q", envByName["LEGACY_FORM"])
	}
	if len(tei.Command) != 1 || tei.Command[0] != "text-embeddings-router" {
		t.Errorf("entrypoint = %v", tei.Command)
	}
	if len(tei.Args) != 2 || tei.Args[0] != "--model-id" {
		t.Errorf("cmd args = %v", tei.Args)
	}
}

func TestAppendContainerImagePackageDigestHandling(t *testing.T) {
	valid := "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	var pkgs []ScopedPackage
	seen := map[string]bool{}
	appendContainerImagePackage(&pkgs, seen, "ghcr.io/org/app:v1.2.3@"+valid, "f")
	appendContainerImagePackage(&pkgs, seen, "ghcr.io/org/bad@sha256:zzz", "f")
	appendContainerImagePackage(&pkgs, seen, "ghcr.io/org/pinned@"+valid, "f")
	if len(pkgs) != 3 {
		t.Fatalf("got %d pkgs", len(pkgs))
	}
	tagged := pkgs[0]
	if tagged.Version != "v1.2.3" {
		t.Errorf("tag must be the version, got %q", tagged.Version)
	}
	if len(tagged.Checksums) != 1 || tagged.Checksums[0].Alg != "SHA-256" || len(tagged.Checksums[0].Value) != 64 {
		t.Errorf("valid digest must become a checksum: %+v", tagged.Checksums)
	}
	bad := pkgs[1]
	if bad.Version != "" || len(bad.Checksums) != 0 {
		t.Errorf("malformed digest must never become a version or checksum: %+v", bad)
	}
	pinned := pkgs[2]
	if pinned.Version != valid || len(pinned.Checksums) != 1 {
		t.Errorf("digest-pinned (no tag) keeps digest as version + checksum: %+v", pinned)
	}
}

func TestParseKubernetesScopedCRDImages(t *testing.T) {
	pkgs, err := parseKubernetesScoped([]byte(crdYAML), "crd.yaml")
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range pkgs {
		if p.Name == "pytorch/pytorch" && p.Version == "2.4.0-cuda12.1-cudnn9-runtime" {
			found = true
		}
	}
	if !found {
		t.Errorf("PyTorchJob-embedded image not extracted by the container track: %+v", pkgs)
	}
}

func TestParseDockerfileWorkloadShellForm(t *testing.T) {
	df := "FROM vllm/vllm-openai:v0.6.3\nCMD python -m vllm.entrypoints.openai.api_server --model mistralai/Mistral-7B-Instruct-v0.3\n"
	w := ParseDockerfileWorkload([]byte(df), "Dockerfile")
	if w == nil || len(w.Containers) != 1 {
		t.Fatal("workload not parsed")
	}
	args := w.Containers[0].Args
	found := false
	for i, a := range args {
		if a == "--model" && i+1 < len(args) && args[i+1] == "mistralai/Mistral-7B-Instruct-v0.3" {
			found = true
		}
	}
	if !found {
		t.Errorf("shell-form --model not tokenized: %v", args)
	}
}

package faultfixture

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDockerDeploymentFiles_DefineHealthCheckAndReplicaScenarios(t *testing.T) {
	root := filepath.Join("..", "..")
	dockerfile := readFixtureFile(t, filepath.Join(root, "test", "faultfixture", "Dockerfile"))
	for _, want := range []string{"HEALTHCHECK", "-healthcheck", "http://127.0.0.1:8080/health", "USER 65532:65532"} {
		if !strings.Contains(dockerfile, want) {
			t.Fatalf("Dockerfile does not contain %q", want)
		}
	}
	base := readFixtureFile(t, filepath.Join(root, "test", "faultfixture", "compose.yaml"))
	for _, want := range []string{"fault-fixture:", "com.pulse-agent.fixture: fault-fixture", "replicas: 1"} {
		if !strings.Contains(base, want) {
			t.Fatalf("base Compose fixture does not contain %q", want)
		}
	}
	for filename, replicas := range map[string]string{
		"compose.replicas-0.yaml": "replicas: 0",
		"compose.replicas-2.yaml": "replicas: 2",
		"compose.replicas-3.yaml": "replicas: 3",
	} {
		contents := readFixtureFile(t, filepath.Join(root, "test", "faultfixture", filename))
		if !strings.Contains(contents, replicas) {
			t.Fatalf("%s does not contain %q", filename, replicas)
		}
	}
}

func readFixtureFile(t *testing.T, path string) string {
	t.Helper()
	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(contents)
}

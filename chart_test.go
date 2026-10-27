package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"sigs.k8s.io/yaml"
)

func TestChartTokenAudiences(t *testing.T) {
	helm, err := exec.LookPath("helm")
	if err != nil {
		helm = filepath.Join(".tools", "helm")
		if _, err := os.Stat(helm); err != nil {
			t.Skip("Helm required for offline chart rendering; install it or run the existing build-env setup")
		}
	}
	render := func(t *testing.T, values string, wantError bool) []string {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, helm, "template", "test", "./charts/kyverno-notation-aws",
			"--show-only", "templates/deployment.yaml", "--values", "-")
		command.Stdin = strings.NewReader(values)
		output, err := command.CombinedOutput()
		if wantError {
			if err == nil || !strings.Contains(string(output), "deployment.tokenAudiences") {
				t.Fatalf("expected audience validation error, got %v\n%s", err, output)
			}
			return nil
		}
		if err != nil {
			t.Fatalf("helm template: %v\n%s", err, output)
		}
		var deployment struct {
			Spec struct {
				Template struct {
					Spec struct {
						Containers []struct {
							Args []string `json:"args"`
						} `json:"containers"`
					} `json:"spec"`
				} `json:"template"`
			} `json:"spec"`
		}
		data, err := yaml.YAMLToJSON(output)
		requireTestNoError(t, err)
		requireTestNoError(t, json.Unmarshal(data, &deployment))
		if len(deployment.Spec.Template.Spec.Containers) != 1 {
			t.Fatal("expected one verifier container")
		}
		return deployment.Spec.Template.Spec.Containers[0].Args
	}
	baseline := render(t, "{}", false)
	for _, arg := range baseline {
		if strings.HasPrefix(arg, "--tokenAudiences") {
			t.Fatal("default chart must omit tokenAudiences")
		}
	}
	for _, tt := range []struct {
		name   string
		values string
		want   string
	}{
		{"empty list", "deployment:\n  tokenAudiences: []", ""},
		{"one audience", "deployment:\n  tokenAudiences: [kyverno-svc.kyverno.io]", "--tokenAudiences=kyverno-svc.kyverno.io"},
		{"multiple audiences", "deployment:\n  tokenAudiences: [kyverno-svc.kyverno.io, second-audience]", "--tokenAudiences=kyverno-svc.kyverno.io,second-audience"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			args := render(t, tt.values, false)
			if tt.want != "" {
				if slices.Index(args, tt.want) < 0 {
					t.Fatalf("missing argument %q: %v", tt.want, args)
				}
				args = slices.DeleteFunc(args, func(arg string) bool { return arg == tt.want })
			}
			if !slices.Equal(args, baseline) {
				t.Fatalf("audience setting changed unrelated arguments: %v, baseline %v", args, baseline)
			}
		})
	}
	for _, value := range []string{`"not-a-list"`, `{name: audience}`, `true`, `42`, `[42]`, `[false]`, `[""]`, `[" "]`, `["a,b"]`, `["a b"]`, `["a\tb"]`, `["a\u00a0b"]`, `["a\u0085b"]`, `[null]`} {
		t.Run("invalid/"+value, func(t *testing.T) {
			render(t, "deployment:\n  tokenAudiences: "+value, true)
		})
	}
}

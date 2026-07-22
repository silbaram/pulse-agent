package docker

import (
	"context"
	"io"
	"time"

	"github.com/moby/moby/client"
)

// NewSDKClient creates the production Docker Engine client with API negotiation enabled.
func NewSDKClient() (Client, error) {
	apiClient, err := client.New(client.FromEnv)
	if err != nil {
		return nil, err
	}
	return &sdkClient{client: apiClient}, nil
}

type sdkClient struct {
	client *client.Client
}

func (c *sdkClient) NegotiateAPIVersion(context.Context) error {
	// The current official SDK negotiates automatically on its first request.
	return nil
}

func (c *sdkClient) Inspect(ctx context.Context, identifier string) (Container, error) {
	result, err := c.client.ContainerInspect(ctx, identifier, client.ContainerInspectOptions{})
	if err != nil {
		return Container{}, err
	}
	container := Container{ID: result.Container.ID}
	if result.Container.State != nil {
		container.Running = result.Container.State.Running
		if result.Container.State.Health != nil {
			container.Health = string(result.Container.State.Health.Status)
		}
	}
	if result.Container.Config != nil {
		container.Labels = cloneLabels(result.Container.Config.Labels)
	}
	return container, nil
}

func (c *sdkClient) ListByLabel(ctx context.Context, key, value string) ([]Container, error) {
	filters := make(client.Filters).Add("label", key+"="+value)
	result, err := c.client.ContainerList(ctx, client.ContainerListOptions{All: true, Filters: filters})
	if err != nil {
		return nil, err
	}
	containers := make([]Container, 0, len(result.Items))
	for _, item := range result.Items {
		health := ""
		if item.Health != nil {
			health = string(item.Health.Status)
		}
		containers = append(containers, Container{ID: item.ID, Running: item.State == "running", Health: health, Labels: cloneLabels(item.Labels)})
	}
	return containers, nil
}

func (c *sdkClient) Logs(ctx context.Context, identifier string) (io.ReadCloser, error) {
	return c.client.ContainerLogs(ctx, identifier, client.ContainerLogsOptions{ShowStdout: true, ShowStderr: true, Tail: "100"})
}

func (c *sdkClient) Restart(ctx context.Context, identifier string, stopTimeout time.Duration) error {
	seconds := int(stopTimeout.Round(time.Second) / time.Second)
	_, err := c.client.ContainerRestart(ctx, identifier, client.ContainerRestartOptions{Timeout: &seconds})
	return err
}

func cloneLabels(labels map[string]string) map[string]string {
	if labels == nil {
		return nil
	}
	cloned := make(map[string]string, len(labels))
	for key, value := range labels {
		cloned[key] = value
	}
	return cloned
}

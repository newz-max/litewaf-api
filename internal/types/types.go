package types

type HealthzResp struct {
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
	Time   string `json:"time"`
}

type VersionResp struct {
	Name                     string `json:"name"`
	Version                  string `json:"version"`
	Env                      string `json:"env"`
	GatewayClientMaxBodySize string `json:"gateway_client_max_body_size"`
}

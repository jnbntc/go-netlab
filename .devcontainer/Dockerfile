{
    "name": "Netlab Go Stack",
    "image": "mcr.microsoft.com/devcontainers/go:1-1.22-bookworm",
    "customizations": {
        "vscode": {
            "settings": {
                "go.toolsManagement.checkForUpdates": "local",
                "go.useLanguageServer": true,
                "go.gopath": "/go",
                "go.lintTool": "golangci-lint",
                "go.lintFlags": ["--fast"]
            },
            "extensions": [
                "golang.go",
                "golang.golangci-lint"
            ]
        }
    },
    "forwardPorts": [8080],
    "remoteUser": "vscode",
    "postCreateCommand": "go version && go install github.com/go-delve/delve/cmd/dlv@latest"
}

# WatchDog — GitLab Duo Agent Platform

This directory contains the GitLab Duo Agent Platform configuration for **WatchDog**, a security scanner that catches leaked credentials, client-side secret exposure, and misconfigurations before deployment.

## Source Code

The full source code, documentation, and tests are available on GitHub:

**[github.com/eliaslehner/WatchDog](https://github.com/eliaslehner/WatchDog)**

## Structure

```
gitlab/
├── agents/
│   ├── agent.yml            # WatchDog agent definition
│   └── agent.yml.template   # Agent template
├── flows/
│   ├── flow.yml             # WatchDog flow definition
│   └── flow.yml.template    # Flow template
├── test-app/                # Intentionally vulnerable sample app for demos
│   ├── .env                 # Example environment file
│   ├── config.py            # Example config with misconfigurations
│   ├── docker-compose.yml   # Docker Compose setup
│   ├── Dockerfile           # Container definition
│   └── frontend.jsx         # Frontend with client-side exposure
├── LICENSE                  # MIT License
├── RULES.md                 # Hackathon official rules
└── README.md                # This file
```

## Getting Started

For local setup and usage instructions, see the [main README](https://github.com/eliaslehner/WatchDog#readme).
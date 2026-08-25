# ubuntu-ai-cline-coder

A self-contained Ubuntu image for running AI coding workflows. It bundles
**git**, **npm** (Node.js LTS), the **Cline CLI**, and common development tools.
The container starts in **bash** by default — run `cline ...` from that shell
when you want to drive an AI agent.

## What's included

| Tool            | Why                                             |
| --------------- | ----------------------------------------------- |
| `git`           | VCS — Cline interacts heavily with repos        |
| `node` / `npm`  | Node.js LTS + npm                               |
| `cline`         | The Cline CLI (`npm i -g cline`, binary `cline`)|
| `python3`/`pip` | Common dev/runtime dependency                   |
| `build-essential` | Compilers (gcc/g++/make) for native modules  |
| `jq`, `ripgrep`, `wget`, `curl`, `unzip`/`zip` | CI/scripting helpers |
| `vim`, `nano`, `less`, `tree`, `htop` | Editing & inspection |

## Build

```bash
docker build -t ai-cline-coder .
```

Switch Node.js major version (defaults to `24` LTS):

```bash
docker build --build-arg NODE_MAJOR=22 -t ai-cline-coder .
```

## API keys

The image accepts API keys from the current environment two ways.

### 1. Runtime injection (recommended)

Pass keys when the container starts — nothing secret is baked into the image:

```bash
# from your shell environment
docker run -it -v "$PWD:/workspace" \
  -e ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY" \
  ai-cline-coder

# or from a .env file (see .env.example)
docker run -it -v "$PWD:/workspace" --env-file .env ai-cline-coder
```

### 2. Build-time injection

If you want a throwaway image with keys baked in, pass them as build args.
⚠️ **Security note:** these become part of the image layers and are visible in
`docker history`. Prefer runtime injection for anything shared or pushed.

```bash
docker build \
  --build-arg ANTHROPIC_API_KEY="$ANTHROPIC_API_KEY" \
  --build-arg OPENAI_API_KEY="$OPENAI_API_KEY" \
  -t ai-cline-coder .
```

Supported keys (passed through from the host environment): `ANTHROPIC_API_KEY`,
`ANTHROPIC_BASE_URL`, `OPENAI_API_KEY`, `OPENAI_BASE_URL`, `OPENROUTER_API_KEY`,
`DEEPSEEK_API_KEY`, `GEMINI_API_KEY`, `GOOGLE_GENERATIVE_AI_API_KEY`,
`MISTRAL_API_KEY`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`,
`AWS_SESSION_TOKEN`. These are injected into the container so any tool that reads
them has access.

### Using a provider (e.g. OpenRouter)

Cline accepts a key two ways:

**a) Environment variable + `-P` (per-run, no config file).** When you select a
provider with `-P`, Cline reads the matching env var (`OPENROUTER_API_KEY`,
`ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, …). For OpenRouter:

```bash
docker run --rm -v "$PWD:/workspace" \
  -e OPENROUTER_API_KEY="$OPENROUTER_API_KEY" \
  ai-cline-coder cline -P openrouter -m anthropic/claude-sonnet-4 "your task"
```

**b) `cline auth` (persists to `~/.cline`).** Non-interactively:

```bash
docker run --rm -v cline-data:/root/.cline \
  -e OPENROUTER_API_KEY="$OPENROUTER_API_KEY" \
  ai-cline-coder cline auth --provider openrouter \
    --apikey "$OPENROUTER_API_KEY" --modelid anthropic/claude-sonnet-4
```

Persist `~/.cline` with a named volume so authentication survives across runs,
then run without repeating the key:

```bash
docker run -it \
  -v cline-data:/root/.cline \
  -v "$PWD:/workspace" \
  ai-cline-coder cline "your task"
```

Interactive auth (pick provider/model from a menu) is also available:

```bash
docker run -it -v cline-data:/root/.cline ai-cline-coder cline auth
```

Other useful Cline env vars (see `cline` docs): `CLINE_DATA_DIR`
(custom config dir), `CLINE_COMMAND_PERMISSIONS` (JSON allow/deny policy for
shell commands). Pass them with `-e` like any other variable.

## Memory / rules

A global rules file (`cline.md` — tone/style guidelines) is baked into the
image at `/root/.cline/rules/cline.md` and `/root/Documents/Cline/Rules/cline.md`.
Cline loads it at the start of **every** session, in **every** project.

- **Project-specific rules**: add `.md` files to `.clinerules/` in any repo you
  mount — they're combined with (and take precedence over) the global rules.
- **Your own global rules**: write files into `/root/.cline/rules/` with the
  `cline-data` volume mounted to persist them outside the image.

## Usage

### Mount your current directory

`-v "$PWD:/workspace"` mounts your **current directory** into `/workspace`
inside the container (the container's working directory). Cline edits the same
files on disk, so changes show up in your repo immediately.

```bash
# Interactive bash shell in your project (keys from your env / .env)
docker run -it --rm -v "$PWD:/workspace" --env-file .env ai-cline-coder
```

You land in `/workspace` as a `bash` shell. From there, run Cline:

```bash
cline -P openrouter -m anthropic/claude-sonnet-4 "your task"
```

### One-shot Cline task (no shell, runs and exits)

```bash
docker run --rm -v "$PWD:/workspace" \
  -e OPENROUTER_API_KEY="$OPENROUTER_API_KEY" \
  ai-cline-coder cline -P openrouter -m anthropic/claude-sonnet-4 \
    "summarize this repo"
```

More examples:

```bash
# Plan-first, then act
docker run --rm -v "$PWD:/workspace" --env-file .env \
  ai-cline-coder cline --plan "design a migration plan"

# Fully autonomous (auto-approve tool calls)
docker run --rm -v "$PWD:/workspace" --env-file .env \
  ai-cline-coder cline --auto-approve true "run tests and fix failures"

# Pipe context in (headless mode)
git diff | docker run --rm -i -v "$PWD:/workspace" --env-file .env \
  ai-cline-coder cline "review these changes"
```

### Common flags

| Flag | What it does |
|------|--------------|
| `-it` | Interactive TTY (for the shell / interactive prompts) |
| `--rm` | Delete the container when it exits |
| `-v "$PWD:/workspace"` | Mount current dir → `/workspace` in the container |
| `-e KEY="$KEY"` | Pass one env var from your shell |
| `--env-file .env` | Pass many keys from a file |

The working directory inside the container is `/workspace`; mount your repo
there with `-v "$PWD:/workspace"`. On Windows PowerShell use `${PWD}` (or
`$(pwd)` in Git Bash/WSL). To persist Cline's auth config across runs, add
`-v cline-data:/root/.cline`.
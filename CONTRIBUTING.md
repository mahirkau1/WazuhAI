# Contributing

Thanks for helping improve AegisAI Agent.

## Development workflow

1. Create a branch for your change.
2. Keep changes focused and defensive in purpose.
3. Do not commit secrets, `.env`, databases, logs, virtual environments, or generated cache files.
4. Run a syntax check before opening a pull request:

```bash
python -m py_compile app/*.py
```

5. Describe what changed, how it was tested, and any security impact.

## Security-focused contributions

Detection rules and testing examples should be designed for authorized defensive use. Avoid including live credentials, private infrastructure details, or unnecessary weaponized exploit code.

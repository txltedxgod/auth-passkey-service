# Contributing Guidelines

Thank you for your interest in contributing!

## Code of Conduct
We are committed to providing a welcoming, inclusive, and harassment-free environment for everyone.

## Development Workflow
1. Fork the repository and create your branch from `main`:
   ```bash
   git checkout -b feat/your-feature-name
   ```
2. Ensure dependencies are installed and test suites pass:
   ```bash
   make test
   ```
3. Commit your changes using Conventional Commits (`feat: ...`, `fix: ...`, `docs: ...`, `perf: ...`).
4. Push to your fork and submit a Pull Request.

## Code Quality Standards
- Write clean, type-annotated, modular code.
- Add comprehensive unit and integration tests for all new code paths.
- Maintain backward compatibility where possible.

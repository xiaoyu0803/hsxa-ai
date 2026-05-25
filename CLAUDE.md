# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Go project. IDE: GoLand (`/usr/local/go`).

## Common Commands

```bash
go build ./...        # build
go test ./...         # run all tests
go test ./pkg/... -run TestFoo  # run a single test
go vet ./...          # lint
gofmt -w .            # format
```
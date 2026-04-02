# Makefile for copilot-shell

.PHONY: help deps deps-ci build bundle test lint format preflight clean start debug rpm install uninstall

# ── Variables ──
DESTDIR  ?=
PREFIX   ?= /usr/local
LIBDIR    = $(PREFIX)/lib/copilot-shell
DATADIR   = $(PREFIX)/share/copilot-shell
BINDIR    = $(PREFIX)/bin

help:
	@echo "Makefile for copilot-shell"
	@echo ""
	@echo "Development:"
	@echo "  make deps             - Install npm dependencies"
	@echo "  make build            - Build the project"
	@echo "  make test             - Run the test suite"
	@echo "  make lint             - Lint the code"
	@echo "  make format           - Format the code"
	@echo "  make preflight        - Run formatting, linting, and tests"
	@echo "  make clean            - Remove generated files"
	@echo "  make start            - Start the Copilot Shell"
	@echo "  make debug            - Start the Copilot Shell in debug mode"
	@echo ""
	@echo "Packaging & Install:"
	@echo "  make deps-ci          - Clean-install npm deps (CI / RPM build)"
	@echo "  make bundle           - Bundle for distribution"
	@echo "  make install          - Install to PREFIX (supports DESTDIR for RPM)"
	@echo "  make uninstall        - Remove installed files"
	@echo "  make rpm              - Build an RPM package"

deps:
	npm install

deps-ci:
	npm ci --ignore-scripts

build:
	npm run build

bundle:
	npm run bundle
	npm run prepare:package

test:
	npm run test

lint:
	npm run lint

format:
	npm run format

preflight:
	npm run preflight

clean:
	npm run clean

start:
	npm run start

debug:
	npm run debug

rpm:
	npm run package:rpm

# ── Install ──
# RPM build:   make install DESTDIR=%{buildroot} PREFIX=/usr
# Direct:      sudo make install PREFIX=/usr/local
install: dist/cli.js
	@echo "Installing copilot-shell to $(DESTDIR)$(LIBDIR) ..."
	install -d "$(DESTDIR)$(LIBDIR)"
	cp -pr dist/* "$(DESTDIR)$(LIBDIR)/"
	@if [ -d hooks ]; then \
		install -d "$(DESTDIR)$(DATADIR)/hooks"; \
		cp -pr hooks/* "$(DESTDIR)$(DATADIR)/hooks/"; \
	fi
	install -d "$(DESTDIR)$(BINDIR)"
	printf '#!/bin/bash\nexec node "%s/cli.js" "$$@"\n' "$(LIBDIR)" > "$(DESTDIR)$(BINDIR)/cosh"
	chmod 755 "$(DESTDIR)$(BINDIR)/cosh"
	ln -sf cosh "$(DESTDIR)$(BINDIR)/co"
	ln -sf cosh "$(DESTDIR)$(BINDIR)/copilot"
	@echo "Installed: $(DESTDIR)$(BINDIR)/{cosh,co,copilot}"

uninstall:
	rm -f "$(DESTDIR)$(BINDIR)/cosh" "$(DESTDIR)$(BINDIR)/co" "$(DESTDIR)$(BINDIR)/copilot"
	rm -rf "$(DESTDIR)$(LIBDIR)"
	rm -rf "$(DESTDIR)$(DATADIR)"
	@echo "Uninstalled copilot-shell from $(DESTDIR)$(PREFIX)"

.PHONY: all test clean deb appimage install install-deps install-policy install-snx-rs

VENV        := .venv
PYTHON      := $(VENV)/bin/python
VERSION     := $(shell tr -d '[:space:]' < VERSION 2>/dev/null || echo "0.1.0")
# snx-rs release to install when not already present.
SNX_RS_VER  := 5.2.0
# Map dpkg architecture names to snx-rs release file names.
_DPKG_ARCH  := $(shell dpkg --print-architecture 2>/dev/null || echo x86_64)
SNX_RS_ARCH := $(shell echo $(_DPKG_ARCH) | sed 's/amd64/x86_64/;s/arm64/arm64/')

all: test

$(VENV):
	python3 -m venv --system-site-packages $(VENV)

# Install application: system packages, Python package, binary and desktop integration
install: $(VENV) install-snx-rs
	find $(VENV)/lib -maxdepth 4 -name '~nxui*' -type d -exec rm -rf {} + 2>/dev/null || true
	sudo apt-get install -y python3-gi gir1.2-gtk-4.0 gir1.2-adw-1 \
	    python3-dbus python3-keyring python3-secretstorage python3-pexpect \
	    python3-filelock
	$(VENV)/bin/pip install -e .
	sudo install -Dm755 $(VENV)/bin/snxui /usr/local/bin/snxui
	sudo install -Dm644 snxui/data/com.snxui.policy \
	    /usr/share/polkit-1/actions/com.snxui.policy
	sudo install -Dm644 snxui/data/snxui.desktop \
	    /usr/share/applications/snxui.desktop
	sudo install -Dm644 snxui/data/icons/snxui.svg \
	    /usr/share/icons/hicolor/scalable/apps/snxui.svg
	sudo gtk-update-icon-cache /usr/share/icons/hicolor/ -t

# Install dev/build dependencies on top of base install
install-deps: install
	$(VENV)/bin/pip install -e ".[dev]"
	sudo apt-get install -y debhelper devscripts

test:
	$(PYTHON) -m pytest tests/ -v

test-coverage:
	$(PYTHON) -m pytest tests/ --cov=snxui --cov-report=html

lint:
	$(PYTHON) -m mypy snxui/ --ignore-missing-imports
	$(PYTHON) -m black snxui/ --check

format:
	$(PYTHON) -m black snxui/

deb:
	bash scripts/build-release.sh $(VERSION)
	@echo "DEB package created: snxui_$(VERSION)_all.deb"

appimage: test
	bash packaging/appimage/build-appimage.sh $(VERSION)

uninstall:
	$(PYTHON) -m pip uninstall snxui -y
	sudo rm -f /usr/local/bin/snxui
	sudo rm -f /usr/share/polkit-1/actions/com.snxui.policy
	sudo rm -f /usr/share/applications/snxui.desktop
	sudo rm -f /usr/share/icons/hicolor/scalable/apps/snxui.svg

install-policy:
	sudo install -Dm644 snxui/data/com.snxui.policy \
	    /usr/share/polkit-1/actions/com.snxui.policy

# Install snx-rs if missing or outdated.
# Skips download when the installed version already matches SNX_RS_VER.
install-snx-rs:
	@INSTALLED=$$(snxctl --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1 || echo ""); \
	if [ "$$INSTALLED" = "$(SNX_RS_VER)" ]; then \
	    echo "snx-rs: v$(SNX_RS_VER) already installed, skipping."; \
	else \
	    if [ -n "$$INSTALLED" ]; then \
	        echo "snx-rs: upgrading v$$INSTALLED → v$(SNX_RS_VER)..."; \
	    else \
	        echo "snx-rs: not found, installing v$(SNX_RS_VER)..."; \
	    fi; \
	    TMP=$$(mktemp /tmp/snx-rs-XXXXXX.deb) && \
	    URL="https://github.com/ancwrd1/snx-rs/releases/download/v$(SNX_RS_VER)/snx-rs-v$(SNX_RS_VER)-linux-$(SNX_RS_ARCH).deb" && \
	    echo "  Downloading $$URL ..." && \
	    curl -fL -o "$$TMP" "$$URL" && \
	    sudo dpkg -i "$$TMP" && \
	    rm -f "$$TMP" && \
	    echo "snx-rs $(SNX_RS_VER) installed."; \
	fi

clean:
	find . -name "*.pyc" -delete
	find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
	rm -rf build/ dist/ *.egg-info/ htmlcov/ .coverage AppDir/ snxui-*.AppImage
	rm -f snxui_*.deb snxui_*.changes snxui_*.buildinfo
	rm -rf $(VENV)

.PHONY: all test clean deb appimage install-deps install-policy

PYTHON  := python3
VERSION := $(shell tr -d '[:space:]' < VERSION 2>/dev/null || echo "0.1.0")

all: test

install-deps:
	$(PYTHON) -m pip install -e ".[dev]"
	sudo apt-get install -y python3-gi gir1.2-gtk-4.0 gir1.2-adw-1 \
	    python3-dbus python3-keyring python3-secretstorage python3-pexpect \
	    python3-filelock debhelper devscripts

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

install:
	sudo $(PYTHON) -m pip install -e .
	sudo install -Dm644 snxui/data/com.snxui.policy \
	    /usr/share/polkit-1/actions/com.snxui.policy
	sudo install -Dm644 snxui/data/snxui.desktop \
	    /usr/share/applications/snxui.desktop
	sudo install -Dm644 snxui/data/icons/snxui.svg \
	    /usr/share/icons/hicolor/scalable/apps/snxui.svg
	sudo gtk-update-icon-cache /usr/share/icons/hicolor/ -t

uninstall:
	sudo $(PYTHON) -m pip uninstall snxui -y
	sudo rm -f /usr/share/polkit-1/actions/com.snxui.policy
	sudo rm -f /usr/share/applications/snxui.desktop
	sudo rm -f /usr/share/icons/hicolor/scalable/apps/snxui.svg

install-policy:
	sudo install -Dm644 snxui/data/com.snxui.policy \
	    /usr/share/polkit-1/actions/com.snxui.policy

clean:
	find . -name "*.pyc" -delete
	find . -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true
	rm -rf build/ dist/ *.egg-info/ htmlcov/ .coverage AppDir/ snxui-*.AppImage
	rm -f snxui_*.deb snxui_*.changes snxui_*.buildinfo

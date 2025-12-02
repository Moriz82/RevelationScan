PYTHON ?= python3
SRC     = src
PACKAGE = RevelationScan
DISTDIR = dist
BUILD   = build

.PHONY: run bundle compile clean binary test

run:
	PYTHONPATH=$(SRC) $(PYTHON) -m $(PACKAGE).cli $(ARGS)

bundle:
	mkdir -p $(DISTDIR)
	$(PYTHON) -m zipapp $(SRC) -m $(PACKAGE).cli:main -o $(DISTDIR)/RevelationScan.pyz

compile:
	$(PYTHON) -m compileall $(SRC)

binary:
	@command -v pyinstaller >/dev/null 2>&1 || { echo "pyinstaller is required for the bin"; exit 1; }
	pyinstaller --clean --onefile --name RevelationScan $(SRC)/$(PACKAGE)/__main__.py
	mkdir -p $(DISTDIR)
	cp dist/RevelationScan $(DISTDIR)/RevelationScan

clean:
	rm -rf $(DISTDIR) $(BUILD) $(SRC)/$(PACKAGE)/__pycache__ __pycache__ build __pycache__ *.spec dist/__pycache__
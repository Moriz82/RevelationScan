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
	@command -v pyinstaller >/dev/null 2>&1 || { echo "pyinstaller is required for the binary target"; exit 1; }
	pyinstaller --clean --onefile --name revelation-scan $(SRC)/$(PACKAGE)/__main__.py
	mkdir -p $(DISTDIR)
	cp dist/revelation-scan $(DISTDIR)/revelation-scan

clean:
	rm -rf $(DISTDIR) $(BUILD) $(SRC)/$(PACKAGE)/__pycache__ __pycache__ build __pycache__ *.spec dist/__pycache__

test:
	PYTHONPATH=$(SRC) $(PYTHON) -m unittest discover -s tests

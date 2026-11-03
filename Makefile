.PHONY: gate
gate:
	CORNICEN_FUZZ_CASES=$${CORNICEN_FUZZ_CASES:-2000} PYTHONPATH=src python3 -m unittest discover -s tests -t . -v

default: test

test:
	qlot exec ros run --eval '(asdf:test-system :cl-sbom)' --eval '(quit)'

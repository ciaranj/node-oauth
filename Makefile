#
# Run all tests
#
test:
	@@vows tests/* --spec

.PHONY: test install
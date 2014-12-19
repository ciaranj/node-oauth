#
# Run all tests
#
test:
	@@node_modules/.bin/vows tests/*.js --spec

.PHONY: test install

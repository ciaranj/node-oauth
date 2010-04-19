
NODE = node

all: test
	
test:
	@$(NODE) spec/node.js all
	
.PHONY: test
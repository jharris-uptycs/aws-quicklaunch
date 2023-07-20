
PROJECT = UptycsAccountHandler
DIR_NAME = uptycs_account_handler
FUNCTION = $(PROJECT)-$(VERSION)
DIST_DIR ?= ../../functions/packages/$(DIR_NAME)
VERSION=0.0.1


all: build

.PHONY: clean build

clean:
	rm -rf build
	rm $(DIST_DIR)/$(FUNCTION).zip || true

build: clean
	mkdir -p build
	cp ../common/common_functions.py build
	cp uptycs_account_handler.py build
	sed -e "s/\BUILD_VERSION/$$(VERSION_ENV)/g" uptycs_account_handler.py > build/uptycs_account_handler.py
	pip3 install -r requirements.txt -t build
	cd build && zip -r ../$(DIST_DIR)/$(FUNCTION).zip . -x "*.DS_Store*" "*.git*" "build*" "Makefile"
	rm -rf build

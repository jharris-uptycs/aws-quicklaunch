

KEY_PREFIX := uptycs-ct-quicklaunch
PACKAGES_PREFIX := lambda/
CFT_PREFIX := templates
CFT_DIR := cloudformation


PROFILE ?= default
REGION ?= eu-west-1

BUCKET_NAME ?= uptycs-cloud-integrations-test
BASE = $(shell /bin/pwd)

s3_buckets := $(BUCKET_NAME)

#TOPTARGETS := all clean package build

SUBDIRS := $(wildcard lambda_functions/functions/source/*/.)
$(info Value of SUBDIRS is $(SUBDIRS))
ZIP_SUBDIRS := $(wildcard lambda_functions/functions/packages/*/.)
$(info Value of ZIP_SUBDIRS is $(ZIP_SUBDIRS))
ZIP_FILES := $(shell find $(ZIP_SUBDIRS) -type f -name '*.zip' -exec echo {} \;)
$(info Value of ZIP_FILES is $(ZIP_FILES))

#$(TOPTARGETS): $(SUBDIRS)

$(SUBDIRS):
	$(MAKE) -C $@ $(MAKECMDGOALS) $(ARGS) BASE="${BASE}" DATASET="${DATASET}"




upload: $(s3_buckets)

$(s3_buckets):
	$(info [+] Uploading artifacts to '$@' bucket)
	@$(MAKE) _upload BUCKET_NAME=$@
	@$(MAKE) _upload_zip BUCKET_NAME=$@

_upload:
	$(info [+] Uploading templates to $(BUCKET_NAME) bucket)
	@aws --profile $(PROFILE) --region $(REGION) s3 cp $(CFT_DIR)/ s3://$(BUCKET_NAME)/$(KEY_PREFIX)/$(CFT_PREFIX) --recursive --exclude "*" --include "*.yaml" --include "*.json" --include "*.yml" --acl public-read

_upload_zip: $(ZIP_SUBDIRS)

$(ZIP_SUBDIRS): $(ZIP_FILES)

$(ZIP_FILES):
	$(info [+] Uploading zip files to $(BUCKET_NAME) bucket)
	@aws --profile $(PROFILE) --region $(REGION) s3 cp $@ s3://$(BUCKET_NAME)/$(KEY_PREFIX)/$(PACKAGES_PREFIX) --acl public-read

.PHONY: $(TOPTARGETS) $(SUBDIRS) $(s3_buckets) $(ZIP_FILES)
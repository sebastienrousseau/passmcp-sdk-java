# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: Apache-2.0

JAVAC ?= javac
JAVA ?= java
JAVAC_FLAGS := --release 21 -encoding UTF-8 -Xlint:all -Werror

MAIN_CLASSES := target/classes
TEST_CLASSES := target/test-classes
EXAMPLE_CLASSES := target/example-classes

MAIN_SOURCES := $(wildcard src/main/java/com/satellion/passmcp/sdk/*.java)
TEST_SOURCES := $(wildcard src/test/java/com/satellion/passmcp/sdk/*.java)
EXAMPLE_SOURCES := $(wildcard examples/*.java)

LOCAL_ECOSYSTEM := $(abspath ../../Go/passmcp/ecosystem.json)
ifneq ($(wildcard $(LOCAL_ECOSYSTEM)),)
PASSMCP_ECOSYSTEM_URL ?= file://$(LOCAL_ECOSYSTEM)
endif

.PHONY: all check build lint test reuse family lockstep example clean

all: check

check: lint test reuse family lockstep example

build:
	@mkdir -p $(MAIN_CLASSES)
	$(JAVAC) $(JAVAC_FLAGS) -d $(MAIN_CLASSES) $(MAIN_SOURCES)

lint: build
	@mkdir -p $(TEST_CLASSES) $(EXAMPLE_CLASSES)
	$(JAVAC) $(JAVAC_FLAGS) -cp $(MAIN_CLASSES) -d $(TEST_CLASSES) $(TEST_SOURCES)
	$(JAVAC) $(JAVAC_FLAGS) -cp $(MAIN_CLASSES) -d $(EXAMPLE_CLASSES) $(EXAMPLE_SOURCES)

test: lint
	$(JAVA) -ea -cp $(MAIN_CLASSES):$(TEST_CLASSES) com.satellion.passmcp.sdk.SdkTestRunner

reuse:
	reuse lint

family:
	PASSMCP_ECOSYSTEM_URL="$(PASSMCP_ECOSYSTEM_URL)" ./scripts/family.sh

lockstep:
	./scripts/lockstep.sh

example: lint
	$(JAVA) -ea -cp $(MAIN_CLASSES):$(EXAMPLE_CLASSES) Quickstart

clean:
	rm -rf target

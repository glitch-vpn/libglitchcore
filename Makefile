# libglitchcore build - single entry point.
#
# Host targets orchestrate Docker; the actual cross-compilation runs inside
# the container via this same Makefile (distinct target names - see the two
# sections below).
#
# Host targets (run these):
#   make build                     full composition (xray+awg+mihomo), all platforms
#   make build ENGINES="xray,awg"  any engine subset (comma/space separated)
#   make test                      unit + integration smoke tests (in the container)
#   make image                     (re)build the Docker toolchain image only
#   make clean                     remove build_output
#   make help                      list targets
#
# Container-only targets (invoked as `docker run <image> <target>`, not by hand):
#   ffi, run-tests
#
# Recipes are POSIX sh: dash-safe inside the Ubuntu build image, and the host's
# GNU Make uses Git's sh on Windows. Paths differ by side: host targets mount
# $(CURDIR); container targets use the fixed /app mount point.

IMAGE          := libglitchcore_builder
WINTUN_VERSION := 0.14.1

# Engine composition (comma/space separated subset of: xray awg mihomo).
ENGINES ?= xray,awg,mihomo

# One shell per recipe, abort on first failure.
.ONESHELL:
.SHELLFLAGS := -ec

.PHONY: build test image clean help ffi run-tests

# ---------------------------------------------------------------------------
# Host targets - Docker orchestration
# ---------------------------------------------------------------------------

help:
	@echo "libglitchcore build:"
	@echo "  make build                     full native libs (all platforms, via Docker)"
	@echo "  make build ENGINES=\"xray,awg\"  any engine subset"
	@echo "  make test                      unit + smoke tests (via Docker)"
	@echo "  make image                     rebuild the Docker toolchain image"
	@echo "  make clean                     remove build_output"

image:
	docker build -t $(IMAGE) -f "$(CURDIR)/Dockerfile" "$(CURDIR)"

build: image
	mkdir -p "$(CURDIR)/build_output"
	docker run --rm \
	  -v "$(CURDIR):/app" \
	  -v "$(CURDIR)/build_output:/app/build_output" \
	  -e GLITCH_ENGINES="$(ENGINES)" \
	  $(IMAGE) ffi

test: image
	docker run --rm \
	  -v "$(CURDIR):/app" \
	  -v "$(CURDIR)/build_output:/app/build_output" \
	  -e GLITCH_ENGINES="$(ENGINES)" \
	  $(IMAGE) run-tests

clean:
	rm -rf "$(CURDIR)/build_output"/*

# ---------------------------------------------------------------------------
# Container targets - the actual cross-compile (need the toolchain image)
# ---------------------------------------------------------------------------

ffi:
	cd /app
	go mod tidy
	XRAY_VER=$$(go list -m -f '{{.Version}}' github.com/xtls/xray-core 2>/dev/null || echo unknown)
	AWG_VER=$$(go list -m -f '{{.Version}}' github.com/amnezia-vpn/amneziawg-go 2>/dev/null || echo unknown)
	MIHOMO_VER=$$(go list -m -f '{{.Version}}' github.com/metacubex/mihomo 2>/dev/null || echo unknown)
	LDFLAGS="-s -w -X main.builtXrayCoreVersion=$$XRAY_VER -X main.builtAmneziawgVersion=$$AWG_VER -X main.builtMihomoVersion=$$MIHOMO_VER"
	ANDROID_LDFLAGS="$$LDFLAGS -extldflags \"-Wl,-z,max-page-size=16384 -Wl,-z,common-page-size=16384\""
	# Engine set -> negative build tags (default: everything in).
	ENGINE_SET=$$(printf '%s' "$${GLITCH_ENGINES:-xray,awg,mihomo}" | tr ',' ' ')
	HAS_XRAY=""; HAS_AWG=""; HAS_MIHOMO=""
	for e in $$ENGINE_SET; do
	  case "$$e" in
	    xray) HAS_XRAY=1 ;;
	    awg) HAS_AWG=1 ;;
	    mihomo) HAS_MIHOMO=1 ;;
	    *) echo "[ERR] unknown engine '$$e' (valid: xray awg mihomo)"; exit 1 ;;
	  esac
	done
	if [ -z "$$HAS_XRAY$$HAS_AWG$$HAS_MIHOMO" ]; then echo "[ERR] empty engine set"; exit 1; fi
	NO_TAGS=""
	if [ -z "$$HAS_XRAY" ]; then NO_TAGS="$$NO_TAGS no_xray"; fi
	if [ -z "$$HAS_AWG" ]; then NO_TAGS="$$NO_TAGS no_awg"; fi
	if [ -z "$$HAS_MIHOMO" ]; then NO_TAGS="$$NO_TAGS no_mihomo"; fi
	if [ -n "$$HAS_MIHOMO" ]; then NO_TAGS="$$NO_TAGS no_tailscale"; fi
	# cmfa gates mihomo's Android package reader; only meaningful with mihomo in.
	CMFA=""
	if [ -n "$$HAS_MIHOMO" ]; then CMFA="cmfa"; fi
	echo "[INFO] engines: $$ENGINE_SET (extra tags:$$NO_TAGS)"
	FFI=/app/build_output/ffi
	rm -rf /app/build_output/*
	# --- Android (arm64 + amd64) ---
	for spec in "arm64:arm64-v8a:aarch64-linux-android21-clang" "amd64:x86_64:x86_64-linux-android21-clang"; do
	  arch=$${spec%%:*}; rest=$${spec#*:}; jni=$${rest%%:*}; cc=$${rest##*:}
	  echo "[INFO] android/$$arch -> $$jni"
	  out="$$FFI/android/$$jni"; mkdir -p "$$out"
	  GOOS=android GOARCH=$$arch CGO_ENABLED=1 \
	    CC="$$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/$$cc" \
	    CGO_CFLAGS="-I$$DART_SDK/include" CGO_LDFLAGS="-landroid -llog" \
	    go build -buildvcs=false -tags="with_gvisor $$CMFA $$NO_TAGS" -buildmode=c-shared -ldflags="$$ANDROID_LDFLAGS" -o "$$out/libglitchcore.so" ./
	  if [ "$$arch" = "arm64" ] && [ -f "$$out/libglitchcore.h" ]; then cp "$$out/libglitchcore.h" "$$FFI/libglitchcore.h"; fi
	done
	echo "[OK] Android libraries built"
	# --- Linux ---
	out="$$FFI/linux"; mkdir -p "$$out"
	GOOS=linux GOARCH=amd64 CGO_ENABLED=1 CC=gcc \
	  go build -buildvcs=false -tags="with_gvisor $$NO_TAGS" -buildmode=c-shared -ldflags="$$LDFLAGS" -o "$$out/libglitchcore.so" ./
	[ -f "$$FFI/libglitchcore.h" ] || cp "$$out/libglitchcore.h" "$$FFI/libglitchcore.h"
	echo "[OK] Linux library built"
	# --- Windows (c-shared DLL + service exe) ---
	out="$$FFI/windows"; mkdir -p "$$out"
	GOOS=windows GOARCH=amd64 CGO_ENABLED=1 CC=x86_64-w64-mingw32-gcc \
	  go build -buildvcs=false -tags="with_gvisor $$NO_TAGS" -buildmode=c-shared -ldflags="$$LDFLAGS" -o "$$out/libglitchcore.dll" ./
	GOOS=windows GOARCH=amd64 CGO_ENABLED=1 CC=x86_64-w64-mingw32-gcc \
	  go build -buildvcs=false -tags="service with_gvisor $$NO_TAGS" -ldflags="$$LDFLAGS" -o "$$out/glitch_vpn_core_service.exe" ./
	echo "[OK] Windows libraries built"
	# --- Wintun (cached under /app/.cache) ---
	wt="/app/.cache/wintun-$(WINTUN_VERSION)"
	if [ ! -f "$$wt/wintun.dll" ] || [ ! -f "$$wt/wintun.h" ]; then
	  mkdir -p "$$wt"
	  wget -q -O /tmp/wintun.zip "https://www.wintun.net/builds/wintun-$(WINTUN_VERSION).zip"
	  unzip -o -q -j /tmp/wintun.zip "*/bin/amd64/wintun.dll" -d "$$wt"
	  unzip -o -q -j /tmp/wintun.zip "*/include/wintun.h" -d "$$wt"
	  rm /tmp/wintun.zip
	fi
	cp "$$wt/wintun.dll" "$$wt/wintun.h" "$$FFI/windows/"
	echo "[OK] All FFI libraries in $$FFI"

run-tests:
	cd /app
	ENGINE_SET=$$(printf '%s' "$${GLITCH_ENGINES:-xray,awg,mihomo}" | tr ',' ' ')
	NO_TAGS=""
	case " $$ENGINE_SET " in *" xray "*) ;; *) NO_TAGS="$$NO_TAGS no_xray" ;; esac
	case " $$ENGINE_SET " in *" awg "*) ;; *) NO_TAGS="$$NO_TAGS no_awg" ;; esac
	case " $$ENGINE_SET " in *" mihomo "*) NO_TAGS="$$NO_TAGS no_tailscale" ;; *) NO_TAGS="$$NO_TAGS no_mihomo" ;; esac
	GOOS=linux GOARCH=amd64 CGO_ENABLED=1 CC=gcc CGO_CFLAGS="-I$$DART_SDK/include" \
	  go test -tags="with_gvisor $$NO_TAGS" -count=1 -timeout 120s ./...
	echo "[OK] Tests passed"

FROM eclipse-temurin:19-jdk-focal

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update
RUN apt-get install -y --no-install-recommends ca-certificates
RUN apt-get install -y --no-install-recommends build-essential
RUN apt-get install -y --no-install-recommends wget
RUN apt-get install -y --no-install-recommends curl
RUN apt-get install -y --no-install-recommends git
RUN apt-get install -y --no-install-recommends unzip
RUN apt-get install -y --no-install-recommends rsync
RUN apt-get install -y --no-install-recommends mingw-w64
RUN rm -rf /var/lib/apt/lists/*

ENV GO_VERSION=1.26.4
RUN wget https://golang.org/dl/go${GO_VERSION}.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go${GO_VERSION}.linux-amd64.tar.gz && \
    rm go${GO_VERSION}.linux-amd64.tar.gz
ENV PATH="/usr/local/go/bin:${PATH}"

# Dart SDK: only dart_api_dl.h is needed (the FFI callback glue in the root
# shell includes it).
ENV DART_SDK_VERSION=3.4.3
RUN wget -q https://storage.googleapis.com/dart-archive/channels/stable/release/${DART_SDK_VERSION}/sdk/dartsdk-linux-x64-release.zip -O /tmp/dartsdk.zip \
    && unzip -q /tmp/dartsdk.zip -d /opt \
    && mv /opt/dart-sdk /opt/dart-sdk-${DART_SDK_VERSION} \
    && ln -s /opt/dart-sdk-${DART_SDK_VERSION} /opt/dart-sdk \
    && rm /tmp/dartsdk.zip

ENV DART_SDK="/opt/dart-sdk"
ENV PATH="${DART_SDK}/bin:${PATH}"
ENV CGO_CFLAGS="-I${DART_SDK}/include"

ENV ANDROID_HOME="/opt/android-sdk"
ENV ANDROID_SDK_ROOT="/opt/android-sdk"
ENV ANDROID_NDK_HOME="${ANDROID_SDK_ROOT}/ndk-bundle"
ENV CMDLINE_TOOLS_VERSION="11076708"
ENV NDK_VERSION="27.2.12479018"
ENV BUILD_TOOLS_VERSION="35.0.0"
ENV PLATFORM_VERSION="35"

RUN wget -q https://dl.google.com/android/repository/commandlinetools-linux-${CMDLINE_TOOLS_VERSION}_latest.zip -O /tmp/cmdline-tools.zip && \
    mkdir -p ${ANDROID_SDK_ROOT}/cmdline-tools && \
    unzip -q /tmp/cmdline-tools.zip -d ${ANDROID_SDK_ROOT}/cmdline-tools && \
    mv ${ANDROID_SDK_ROOT}/cmdline-tools/cmdline-tools ${ANDROID_SDK_ROOT}/cmdline-tools/latest && \
    rm /tmp/cmdline-tools.zip

ENV PATH="${ANDROID_SDK_ROOT}/cmdline-tools/latest/bin:${ANDROID_SDK_ROOT}/platform-tools:${PATH}"

RUN yes | sdkmanager --licenses > /dev/null || true
RUN sdkmanager "platform-tools" "platforms;android-${PLATFORM_VERSION}" "build-tools;${BUILD_TOOLS_VERSION}"
RUN sdkmanager "ndk;${NDK_VERSION}"
RUN ln -s ${ANDROID_SDK_ROOT}/ndk/${NDK_VERSION} ${ANDROID_NDK_HOME}

WORKDIR /app

# Module files first so the download layer caches until go.mod/go.sum change.
COPY go.mod go.sum ./
RUN go mod download
COPY . .

# The Makefile is provided live by the -v bind mount at run time (the COPY
# above is a fallback); `docker run <image> <target>` runs `make <target>`
# in /app, e.g. `ffi` or `run-tests`.
ENTRYPOINT ["make"]
CMD ["ffi"]

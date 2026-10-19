# Toolchain for the vendored libsodium.js build. regen.mjs builds this image and runs the build in it.
# Every tool is pinned by image digest, exact package version, or release hash.
FROM emscripten/emsdk:6.0.12@sha256:77638e6c215a65f25a704c0c831d5c2463a8c0468a58c6cb82489dbe621dfa05

# Versions from the noble release pocket, which Ubuntu never changes
RUN apt-get update \
   && apt-get install -y --no-install-recommends autoconf=2.71-3 automake=1:1.16.5-1.3ubuntu1 libtool=2.4.7-7build1 \
   && rm -rf /var/lib/apt/lists/*

# Hashes from the release's SHASUMS256.txt. The baseline x64 build runs on CPUs without AVX2.
ARG BUN_VERSION=1.3.14
RUN set -eu; \
   case "$(uname -m)" in \
      aarch64) asset=bun-linux-aarch64; sum=a27ffb63a8310375836e0d6f668ae17fa8d8d18b88c37c821c65331973a19a3b ;; \
      x86_64) asset=bun-linux-x64-baseline; sum=a063908ae08b7852ca10939bbdc6ceed3ddabce8fb9402dce83d65d73b36e6c7 ;; \
      *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;; \
   esac; \
   curl -fsSL -o /tmp/bun.zip "https://github.com/oven-sh/bun/releases/download/bun-v${BUN_VERSION}/${asset}.zip"; \
   echo "${sum}  /tmp/bun.zip" | sha256sum -c -; \
   unzip -q /tmp/bun.zip -d /tmp/bun; \
   install -m 755 "/tmp/bun/${asset}/bun" /usr/local/bin/bun; \
   rm -rf /tmp/bun /tmp/bun.zip; \
   bun --version

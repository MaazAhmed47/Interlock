FROM python:3.12.9-bookworm@sha256:551c386b532bd5c9a3d84809ebc7d9052771d22c9edb1ccaab0df7307b7bb9e0

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt ./requirements.txt
RUN python -m pip install --requirement requirements.txt \
    && python -m pip install requests==2.32.5

RUN useradd --create-home --uid 10001 interlock
COPY --chown=interlock:interlock . /app
USER interlock

CMD ["sleep", "infinity"]

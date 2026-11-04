# Index digest verified 2026-11-03; see README for updates.
FROM python:3.13-slim@sha256:ae14d4ce8771606477a81446e7ef429edd6762305fc50c84507c1041fa8285d1

ENV PYTHONPATH=/app/src \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN useradd --system --uid 10001 --create-home cornicen \
    && mkdir -p /app /data /config \
    && chown cornicen:cornicen /data /config
WORKDIR /app
COPY --chmod=a+rX src/ /app/src/
USER cornicen
VOLUME ["/data", "/config"]
HEALTHCHECK CMD ["python","-m","cornicen","healthcheck"]
CMD ["python", "-m", "cornicen", "run"]

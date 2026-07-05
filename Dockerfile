# passkit — minimal, reproducible container image.
# Build:  docker build -t passkit .
# Run:    docker run --rm passkit --version
#         docker run --rm passkit challenge --ttl 120
#         echo '{...}' | docker run --rm -i passkit score -
FROM python:3.12-slim

# No .pyc, unbuffered stdout for clean container logs.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Copy project and install with the optional YAML policy support.
COPY . /app
RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir ".[yaml]"

# Run as a non-root user.
RUN useradd --create-home --uid 10001 passkit
USER passkit

ENTRYPOINT ["passkit"]
CMD ["--help"]

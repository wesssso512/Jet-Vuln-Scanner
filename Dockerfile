# Jet Scanner — engine + `jet` CLI + nmap in one image.
#
#   docker build -t jetscanner .
#   docker run --rm jetscanner scan example.com -m all -f json
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY pyproject.toml README.md ./
COPY jetscanner ./jetscanner
RUN pip install --no-cache-dir .

# Run unprivileged: the nmap flags we use (-Pn -F -sV) don't need root.
RUN useradd --create-home --uid 10001 jet
USER jet
WORKDIR /home/jet

ENTRYPOINT ["jet"]
CMD ["--help"]

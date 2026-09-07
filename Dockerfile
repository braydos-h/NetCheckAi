FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

RUN apt-get update \
    # NOTE: metasploit intentionally omitted (image too large); install via INSTALL_KALI_TOOLS=1 ./install.sh on a full host
    && apt-get install -y --no-install-recommends nmap ca-certificates tmux git curl sqlmap nikto gobuster \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt ./
RUN python -m pip install --upgrade pip \
    && python -m pip install -r requirements.txt

COPY . .

RUN mkdir -p reports research_workspace exploit_workspace

EXPOSE 8001 8765

CMD ["python", "main.py", "--doctor"]

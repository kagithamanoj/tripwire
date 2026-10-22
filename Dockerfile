FROM python:3.13-slim
ENV PYTHONUNBUFFERED=1
RUN useradd --create-home app
WORKDIR /app
COPY tripwire ./tripwire
USER app
EXPOSE 8080
HEALTHCHECK CMD python -c "import urllib.request;urllib.request.urlopen('http://localhost:8080/healthz')"
CMD ["python", "-m", "tripwire", "serve", "--port", "8080"]

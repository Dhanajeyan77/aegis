FROM ubuntu:22.04
RUN apt-get update && apt-get install -y python3 curl && rm -rf /var/lib/apt/lists/*
COPY agent.py /root/agent.py
WORKDIR /root
CMD ["python3", "-u", "/root/agent.py"]

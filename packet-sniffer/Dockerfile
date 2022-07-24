FROM python:3.9
WORKDIR /app
RUN apt update -y; apt install -y libpcap-dev
COPY ./requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --upgrade -r /app/requirements.txt
COPY ./sniffer.py /app
CMD ["python3", "-u", "sniffer.py"]

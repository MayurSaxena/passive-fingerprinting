FROM python:3.9
WORKDIR /app
RUN mkdir /app/output
COPY ./requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --upgrade -r /app/requirements.txt
COPY ./*.json /app/
COPY ./api.py /app
CMD ["uvicorn", "api:app", "--proxy-headers", "--host", "0.0.0.0", "--port", "8080"]

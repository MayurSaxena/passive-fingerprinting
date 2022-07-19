# 
FROM python:3.9
WORKDIR /code
COPY ./requirements.txt /code/requirements.txt
COPY ./app /code/app
RUN mkdir /code/output ; pip install --no-cache-dir --upgrade -r /code/requirements.txt
CMD ["uvicorn", "app.main:app", "--proxy-headers", "--host", "0.0.0.0", "--port", "80"]

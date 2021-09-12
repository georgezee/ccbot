#Makefile
.PHONY init deploy test

help:
		@echo "init - set up the application"

init:
		make run

run:
		python app.py

deploy:
		serverless deploy

test:
		pytest tests
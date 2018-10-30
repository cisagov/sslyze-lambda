FROM lambci/lambda:build-python3.6
MAINTAINER Shane Frasier <jeremy.frasier@beta.dhs.gov>

COPY build.sh .
COPY lambda_handler.py .

ENTRYPOINT ["./build.sh"]

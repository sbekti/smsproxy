FROM golang:alpine AS build-env
RUN apk add --update tzdata bash wget curl git
RUN mkdir -p $$GOPATH/bin && \
    curl https://glide.sh/get | sh
ADD . /go/src/smsproxy
WORKDIR /go/src/smsproxy
RUN glide update && go build -o main

FROM alpine
WORKDIR /app
COPY --from=build-env /go/src/smsproxy/main /app/
ENTRYPOINT ["./main"]
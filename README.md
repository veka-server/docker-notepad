# docker-notepad
Simple notepad multi user

## Usage

Build image:
```
docker build -t notepad https://github.com/veka-server/docker-notepad.git#main
```
Usage:
```
docker run --restart unless-stopped -p 9999:80 --name notepad -d notepad
```


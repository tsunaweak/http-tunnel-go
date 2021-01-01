env GOOS=windows GOARCH=amd64 go build  -o .\output\http-tunnel-client-win.exe .\main.go
env GOOS=linux GOARCH=amd64 go build  -o .\output\http-tunnel-client-linux .\main.go
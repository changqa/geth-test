all:
	go build -o bin/main cmd/main.go

clean:
	rm bin/main

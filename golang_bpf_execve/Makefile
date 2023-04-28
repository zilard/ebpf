APP=exec_scrape

.PHONY: build
build: gen $(APP)

.PHONY: run
run: build
	sudo ./$(APP)

.PHONY: gen
gen: sum vmlinux bpf_target gen_execve_bpfel.go

.PHONY: vmlinux
vmlinux: bpf/vmlinux.h

.PHONY: sum
sum: go.sum

.PHONY: fmt
fmt: sum
	go fmt *.go

.PHONY: clean
clean:
	-rm $(APP)
	-rm gen*
	-rm bpf/vmlinux.h
	-rm go.sum
	sed 's/v.*/latest/g' -i go.mod

$(APP): main.go gen_execve_bpfel.go
	CGO_ENABLED=0 go build -o $(APP) *.go

bpf/vmlinux.h:
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h

bpf_target: bpf/execve.bpf.c
	clang -I "/usr/include/" -g -O2 -c -target bpf -o bpf/execve.bpf.o bpf/execve.bpf.c

gen_execve_bpfel.go:
	CC=gcc CGO_CFLAGS="-I /usr/include/" CGO_LDFLAGS="/usr/lib/x86_64-linux-gnu/libbpf.a" go generate *.go

go.sum:
	go mod download github.com/cilium/ebpf
	go get github.com/cilium/ebpf/internal/unix

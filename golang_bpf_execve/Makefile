APP=exec_scrape

.PHONY: build
build: gen $(APP)

.PHONY: run
run: build
	sudo ./$(APP)

.PHONY: gen
gen: sum vmlinux gen_execve_bpfel.go

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

gen_execve_bpfel.go: bpf/execve.bpf.c
	CC=gcc CGO_CFLAGS="-I /usr/include/bpf" CGO_LDFLAGS="/usr/lib64/libbpf.a" go generate *.go

go.sum:
	go mod download github.com/cilium/ebpf
	go get github.com/cilium/ebpf/internal/unix

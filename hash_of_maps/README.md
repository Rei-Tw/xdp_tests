# Installation
- `apt install -y gcc make libelf-dev pkg-config`
- [clang + llvm](https://apt.llvm.org/)
	- `apt install -y lsb-release wget software-properties-common gnupg`
	- `bash -c "$(wget -O - https://apt.llvm.org/llvm.sh)"`

Build l'application en utilisant la commande suivante : `cargo build --release`

# Linux

For Linux users, NanoMQ has provided the following installation methods. 

**Install with Apt/Yum Source**

| OS                                              | Installation Method |
| ----------------------------------------------- | ------------------- |
| Debian-based distributions like Ubuntu          | Apt                 |
| Red Hat-based distributions like CentOS, Fedora | Yum                 |

**Install with Package**

| Architecture | Debian Package (.deb) | RPM Package (.rpm) |
| ------------ | --------------------- | ------------------ |
| **amd64**    | Yes                   | No                 |
| **arm64**    | Yes                   | Yes                |
| **riscv64**  | Yes                   | Yes                |
| **mips**     | Yes                   | Yes                |
| **armhf**    | Yes                   | Yes                |
| **armel**    | Yes                   | Yes                |
| **X86_64**   | No                    | Yes                |

## Install with Apt source

NanoMQ supports installing with Apt source to provide our users with a convenient and reliable way to manage NanoMQ installation and updates. Here is how to install NanoMQ with Apt source:

1. Download the NanoMQ repository:

   ```bash
   curl -s https://assets.emqx.com/scripts/install-nanomq-deb.sh | sudo bash
   ```

2. Install NanoMQ:

   ```bash
   sudo apt-get install nanomq
   ```

3. Start NanoMQ:

   ```bash
   nanomq start  
   ```

## Install with Yum source

For Red Hat-based distributions like CentOS, Fedora, NanoMQ also supports installing with Yum source. Here is how to install NanoMQ with Yum source:

1. Download the NanoMQ repository:

   ```bash
   curl -s https://assets.emqx.com/scripts/install-nanomq-rpm.sh | sudo bash
   ```

2. Install NanoMQ:

   ```bash
   sudo yum install -y nanomq
   ```

3. Start NanoMQ:

   ```bash
   nanomq start  
   ```

## Install with Package

This section takes installing v0.18.2 under the arm64 architecture as an example, for more installation options, you may refer to the [NanoMQ Download](https://nanomq.io/downloads?os=Linux) page.

1. Download [anomq-0.18.2-linux-x86_64.rpm](https://www.emqx.com/en/downloads/nanomq/0.18.2/nanomq-0.18.2-linux-x86_64.rpm).

   ```bash
   wget https://www.emqx.com/en/downloads/nanomq/0.18.2/nanomq-0.18.2-linux-arm64.deb
   ```

2. Install NanoMQ

   ```bash
   sudo apt install ./nanomq-0.18.2-linux-arm64.deb
   ```

3. Run NanoMQ

   ```bash
   nanomq start
   ```

## Install with AUR

The AUR (Arch User Repository) is a community-driven repository for Arch Linux users. It contains package descriptions (PKGBUILDs) that allow you to compile a package from the source and then install it via the Arch Linux package manager (`pacman`). NanoMQ also supports installing with AUR


- Nanomq basic edition

   ```bash
   yay -S nanomq
   ```

- Nanomq sqlite edition

   ```bash
   yay -S nanomq-sqlite
   ```

- Nanomq msquic edition

   ```bash
   yay -S nanomq-msquic
   ```

- Nanomq full edition

   ```bash
   yay -S nanomq-full
   ```






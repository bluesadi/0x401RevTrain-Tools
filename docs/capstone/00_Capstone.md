Capstone是一个轻量级的多平台、多架构的反汇编框架。简单来说，Capstone的功能就是将字节码转化为对应的汇编指令。Capstone目前支持的反汇编架构有：Arm, Arm64 (Armv8), BPF, Ethereum Virtual Machine, M68K, M680X, Mips, MOS65XX, PowerPC, RISCV, Sparc, SystemZ, TMS320C64X, Web Assembly, XCore & X86 (include X86_64)。

## 0x00. 安装

Capstone的安装非常简单，以Python版为例：

```shell
sudo pip install capstone
```

在Windows或root权限下：

```shell
pip install capstone
```

其他的安装方法可以参考[官方文档](http://www.capstone-engine.org/documentation.html)。


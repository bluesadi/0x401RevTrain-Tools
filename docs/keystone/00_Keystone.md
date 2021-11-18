Keystone是一个轻量级的多平台、多架构的汇编框架。简单来说，keystone的功能就是将汇编指令转化为对应的字节码。

[Keystone官方文档](https://www.keystone-engine.org/)

## 0x00. 安装

同Capstone，Keystone可以用pip快速安装：

```sh
$ sudo pip install keystone-engine
```

在Windows或root权限下：

```sh
$ pip install keystone-engine
```

注意这里是`keystone-engine`而不是`keystone`，`keystone`是另外一个模块。

## 0x01. 基本用法

同Capstone，Keystone的API也非常简单，一下是一个将字符串形式的汇编指令转换为字节码的例子：

```python
 from keystone import *

 # separate assembly instructions by ; or \n
 CODE = b"INC ecx; DEC edx"
 
 try:
   # Initialize engine in X86-32bit mode
   ks = Ks(KS_ARCH_X86, KS_MODE_32)
   encoding, count = ks.asm(CODE)
   print("%s = %s (number of statements: %u)" %(CODE, encoding, count))
 except KsError as e:
   print("ERROR: %s" %e)
```

输出：

```python
INC ecx; DEC edx = [65, 74] (number of statements: 2)
```

这段代码非常直观，读者可以通过分析这段代码快速掌握Keystone的用法：

- `Line 1`: 导入Keystone模块。
- `Line 4`: 字符串形式的汇编指令。 这段代码是 X86 架构 Intel 语法的指令。 每条汇编指令之间可以用分号";"或者换行"\n"分隔。
- `Line 8`: 初始化 **Ks** 类。 实例化这个类需要两个参数: 硬件架构和模式。 示例中的硬件架构是X86，模式是32位模式。
- `Line 9`: 使用 **asm** 方法来编译汇编指令. 这个方法会返回一个元组，元组的第一个元素是编译出来的字节码，第二个参数是编译的指令数目。
- `Line 10`: 打印汇编指令的字节码和指令数目。
- `Line 11 ~ 12`: 处理 **KsError** 异常，当编译出现错误时会抛出这个异常。

默认情况下，Keystone使用 Intel 语法解析X86架构的汇编指令，如果要切换为 AT&T 语法，可以使用以下代码：

```python
ks = Ks(KS_ARCH_X86, KS_MODE_32)
ks.syntax = KS_OPT_SYNTAX_ATT
```


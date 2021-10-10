最后一节我们学习如何用angr解决实际问题——利用angr符号执行去除控制流平坦化。在阅读本节教程之前，你需要先了解什么是控制流平坦化，这里不再赘述：

- [Control Flow Flattening](https://github.com/obfuscator-llvm/obfuscator/wiki/Control-Flow-Flattening)
- [基于LLVM Pass实现控制流平坦化 ](https://bbs.pediy.com/thread-266082.htm)

本节的内容主要是是腾讯应急响应中心2017年一篇博客的复现：

- [利用符号执行去除控制流平坦化](https://security.tencent.com/index.php/blog/msg/112)

同时也参考了QuarksLab的这篇博客：

- [Deobfuscation: recovering an OLLVM-protected program](https://blog.quarkslab.com/deobfuscation-recovering-an-ollvm-protected-program.html)

代码主要参考：

- [cq674350529/deflat](https://github.com/cq674350529/deflat/blob/master/flat_control_flow/deflat.py)

## 0x00. 静态分析


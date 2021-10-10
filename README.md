# 0x401RevTrain-Tools

0x401 Team二进制方向逆向辅助分析工具专题培训

## 为什么

在最近的CTF比赛和一些实际场景中，出现了许多光靠人力手动分析和动态调试难以解决的问题，此时往往需要借助一些辅助分析的工具，来帮助我们半自动化，甚至自动化地完成逆向。本专题总结了一些逆向辅助分析神器的原理和用法，并在持续更新中。

## 大纲

- [ ] `capstone`：反汇编框架
- [ ] `keystone`：汇编框架
- [x] `angr`：应用最广泛的符号执行引擎
- [ ] `miasm`：综合了静态分析、符号执行、模拟执行、动态符号执行的集大成逆向框架
- [ ] `unicorn`：基于QEMU的模拟执行引擎
- [ ] `z3`：微软开发的约束求解器（通俗一点就是方程/方程组求解器），是angr和miasm的约束求解实现

## 前置知识

该教程的难度偏进阶，需要读者具有一定的逆向基础，例如：

- C语言编程基础
- Python编程基础
- x86汇编基础
- 一段时间的逆向学习经验

如果读者还不具备以上基础，可以先通过以下的资料学习：

- [逆向入门简介 byRh](https://www.scuctf.com/ctfwiki/reverse/%E9%80%86%E5%90%91%E5%85%A5%E9%97%A8%E7%AE%80%E4%BB%8Bbyrh/)

- [Syclover 技术小组二进制方向招新培训](https://github.com/SycloverTeam/SycRevLearn)
- 各大逆向论坛以及博客
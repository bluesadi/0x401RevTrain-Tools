学习了符号执行的基本原理之后，现在我们可以开始着手学习angr了。

## 0x00. angr的安装

angr的安装十分简单，只需要通过一条简单的pip指令即可完成：

```
pip install angr
```

但根据官方的说法，angr使用的几个依赖项（z3，pyvex等）与官方提供的共享库有所区别，所以为了不让angr自己的z3和pyvex库覆盖官方的z3和pyvex库，我们需要在python虚拟环境中安装angr。

我是用的是Windows上的conda来创建虚拟环境，angr版本为目前最新的angr-9.0.10055，大家可以根据自己的喜好选择操作系统和虚拟环境工具，基本没有区别。

官方的安装教程：[Installing](https://docs.angr.io/introductory-errata/install)，比较简单，我就不再赘述了。

## 0x01. 基本用法

还是先写一个简单的示例程序：

```c++
#include <cstdio>
#include <cstdlib>
#include <cstring>

void encrypt(char* flag){
    for(int i = 0;i < 13;i ++){
        flag[i] ^= i;
        flag[i] += 32;
    }
}

// flag{G00dJ0b}
int main(){
    char flag[100] = {0};
    scanf("%s", flag);
    if(strlen(flag) != 13){
        printf("Wrong length!\n");
        exit(0);
    }
    encrypt(flag);
    if(!strcmp(flag, "\x86\x8d\x83\x84\x9f\x62\x56\x57\x8c\x63\x5a\x89\x91")){
        printf("Right!\n");
    }else{
        printf("Wrong!\n");
    }
}
```

在Ubuntu下编译后得到二进制文件example-1，为什么不在Windows下编译呢，因为Windows下编译的可执行文件在符号执行时会遇到各种各样的问题，为了方便起见就在Ubuntu下编译。

### 加载二进制文件

要使用angr，首先需要加载一个二进制文件：

```python
>>> import angr
>>> proj = angr.Project('example-1')
```

加载后我们可以获取二进制文件的一些属性：

```python
>>> proj.arch
<Arch AMD64 (LE)>
>>> proj.entry
4198688
>>> proj.filename
'example-1'
```

### 符号执行状态——SimStae

现在我们已经把二进制文件加载到到我们的程序中了，接下来我们就要对二进制文件进行符号执行。在上一节中我们提到过，符号执行的过程中要为每条路径维护一个符号状态σ和路径约束PC，对应angr中的`SimState`类：

```python
>>> state = proj.factory.entry_state()
<SimState @ 0x401120>
```

angr中许多类的都需要通过factory获得，factory是工厂的意思，可以理解为proj的factory给用户生产了许多类的实例，这里生产的实例是SimState，entry_state函数用来获取程序入口点的状态，也就是初始状态。

查看state中的一些属性：

```python
>>> state.regs.rip
<BV64 0x401120>
>>> state.regs.rax
<BV64 0x1c>
>>> state.mem[proj.entry].int.resolved
<BV32 0xfa1e0ff3>
```

初始的rip为0x401120，也就是程序的入口点：

![image-20211002223520274](img/image-20211002223520274.png)

在angr中，无论是具体值还是符号量都有相同的类型——claripy.ast.bv.BV，也就是BitVector的意思，BV后面的数字表示这个比特向量的位数。

BV可以通过claripy这个模块创建：

```python
>>> claripy.BVV(666, 32)		# 创建一个32位的有具体值的BV
<BV32 0x29a>
>>> claripy.BVS('sym_var', 32)	# 创建一个32位的符号值BV
<BV32 sym_var_97_32>
```

### 符号执行引擎——Simulation Managers

有了初始状态之后我们就可以对程序进行符号执行了，要进行符号执行，首先得创建一个符号执行引擎：

```python
>>> simgr = proj.factory.simulation_manager(state)
<SimulationManager with 1 active>
```

with 1 active表示当前有一条可以继续延伸的状态，也就是我们初始状态：

```python
>>> simgr.active
[<SimState @ 0x401120>]
```

接下来我们调用simgr的step函数，让符号执行引擎往前执行一步，再来查看当前的状态：

```python
>>> simgr.step()
>>> simgr.active
[<SimState @ 0x500000>]
```

一步步step比较麻烦，我们可以直接让simgr执行到我们的main函数。此时的状态被保存到了found这个数组中，可以通过simgr.found[0]获取当前的状态：

```python
>>> simgr.explore(find=0x401277)
<SimulationManager with 1 found>
>>> simgr.found[0]
<SimState @ 0x401277>
```

Simulation Managers中有若干个这样的数组，也叫作stash，用来保存当前符号执行的所有状态，详情请看：[Stash types](https://docs.angr.io/core-concepts/pathgroups#stash-types)

我们甚至可以直接让simgr执行到输出"Right!"的那条路径：

```python
>>> simgr.explore(find=0x40138F)
<SimulationManager with 1 active, 1 deadended, 1 found>
>>> simgr.found[0]
<SimState @ 0x40138f>
```

然后直接打印当前路径的标准输入来获取flag：

```python
>>> found = simgr.found[0]
>>> found.posix.dumps(0)
b'flag{G00dJ0b}\x00\x00\x00I\x02\x89\x00J\x1a*\x89)\x02*\x00\x00\x1aL\x00\x8a\x1a\x0e\x01\x0e\x08\x89)\x00\x89Y\x02*\x08\x00\x02\x00I\x00\x02\x01(\x00\x08\x8a\x00\x02\x00'
```

第一个\x00之前的字符串也就是flag。这是angr最简单粗暴的用法，但是这种用法并不能体现符号执行和约束求解的本质，不利于我们后面的学习，所以我们换一种写法：

```python
import claripy
import angr

proj = angr.Project('example-1')				
sym_flag = claripy.BVS('flag', 100 * 8)		# BV的大小得设大一点，不然跑不出来，原因未知
state = proj.factory.entry_state(stdin=sym_flag)
simgr = proj.factory.simgr(state)
simgr.explore(find=0x40138D)
solver = simgr.found[0].solver
solver.add(simgr.found[0].regs.eax == 0)
print(solver.eval(sym_flag, cast_to=bytes))
```

输出：

```python
b'flag{G00dJ0b}\x00\x8a\x00\x00*\x00\x00I\x00\x00\x00\x02\x00\x02\x00\x01\x02\x00\x0c\x08\x00I\x8a\x19\x00J\x00\x00K\x18\x1a\x1a+\x00\x01-\x08\x00\x00*\x08\x01\x00***\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
```

我们先让符号执行引擎跑到0x40138D这个地址，也就是跳转到Right或Wrong的jnz指令这：

![image-20211002230150349](img/image-20211002230150349.png)

strcmp函数的返回值保存到eax寄存器内，当strcmp比较成立时eax为0，不成立时eax为1。符号执行的的过程中每个状态都会内置一个约束求解器solver，求解器中保存了当前状态的路径约束PC，所以可以我们在当前状态手动添加新的约束：

```python
solver = simgr.found[0].solver
solver.add(simgr.found[0].regs.eax == 0)
```

然后让约束求解器求解满足符合条件的符号值对应的具体值：

```python
print(solver.eval(sym_flag, cast_to=bytes))
```

这就是angr的基本用法了，之后我们会结合一些CTF的实例来进一步学习angr。


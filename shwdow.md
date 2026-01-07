编译：make
加载：sudo insmod shadow.ko self_hide=0 (建议先以可见模式加载)
隐藏进程：sudo kill -61 <PID>
取消隐藏进程：sudo kill -62 <PID>
隐藏端口：sudo kill -63 <PORT>
取消隐藏端口：sudo kill -64 <PORT>
卸载：sudo rmmod shadow
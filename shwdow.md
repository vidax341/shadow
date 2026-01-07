编译：make
加载：sudo insmod shadow.ko self_hide=0 (建议先以可见模式加载)
隐藏进程：sudo kill -101 <PID>
取消隐藏进程：sudo kill -100 <PID>
隐藏端口：sudo kill -102 <PORT>
取消隐藏端口：sudo kill -103 <PORT>
卸载：sudo rmmod shadow
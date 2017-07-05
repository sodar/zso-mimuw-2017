### Advanced Topics in Operating Systems / Zaawansowane systemy operacyjne

_MIM University of Warsaw, 2016/2017_

-----

#### libinterceptor

`libinterceptor` is a library which enables the user to intercept selected calls from other libraries, such as glibc.
This library exports two functions, `intercept_function` and `unintercept_function`.
These functions substitute original library functions with user-provided ones.
Solution uses libc-provided functions to walk through symbol tables of each dynamically loaded object and modifies GOT entries.

-----

#### monter

`monter` is a driver for Monter&trade; device - accelerator of modular multiplication, which uses Montgomery modular multiplication.
Driver supports multiple user contexts, memory mapping a context and asynchronous command execution.

-----

#### ptrace

Linux kernel patch which adds support for `PTRACE_RUN_SYSCALL` request to `ptrace` syscall.
Tracer process can use `PTRACE_RUN_SYSCALL` to run a selected syscall in tracee's context.
Patch targets Linux kernel 4.9.13.

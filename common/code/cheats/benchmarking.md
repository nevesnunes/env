# +

- [Software optimization resources\. C\+\+ and assembly\. Windows, Linux, BSD, Mac OS X](http://www.agner.org/optimize/)
- [uops\.info: Characterizing Latency, Throughput, and Port Usage of Instructions on Intel Microarchitectures](https://uops.info/)
- [Performance Speed Limits \| Performance Matters](https://travisdowns.github.io/blog/2019/06/11/speed-limits.html)

# methodology

- [Benchmarking: minimum vs average &\#8211; kmod&\#8217;s blog](https://blog.kevmod.com/2016/06/10/benchmarking-minimum-vs-average/)

- [USE Method: Linux Performance Checklist](https://www.brendangregg.com/USEmethod/use-linux.html)
- [Active Benchmarking](https://www.brendangregg.com/activebenchmarking.html)
    - [Active Benchmarking: bonnie\+\+](https://www.brendangregg.com/ActiveBenchmarking/bonnie++.html)
    - [Surge 2013: LightningTalks \- YouTube](http://www.youtube.com/watch?v=vm1GJMp0QN4#t=17m48s)

# environment

- Disabling CPU Frequency Scaling (Maximize frequency)
    ```sh
    sudo cpupower frequency-set --governor performance
    # Validation
    cpupower frequency-info -o proc
    ```
- Warm up CPU
    - e.g. run a pause busy loop on another core
    - https://stackoverflow.com/questions/52465953/assembler-benchmarking-on-intel-using-rdtsc-is-giving-strange-answers-why
- Out-of-order execution
    - serializing instruction (`CPUID` || `LFENCE`) > `RDTSC` > tested code > serializing instruction > `RDTSC`
        - http://www.ccsl.carleton.ca/~jamuir/rdtscpm1.pdf
    - cache line alignment (16-bytes)
    - preventing hoisting: `asm volatile` + `"memory"` clobber (i.e. assumed to read and write every globally-reachable object)
    - https://stackoverflow.com/questions/60291987/idiomatic-way-of-performance-evaluation
        > Increasing the iteration count of a repeat loop should linearly increase the total time, and not affect the calculated time-per-call. 
        > If you're benchmarking two functions in one program: if reversing the order of testing changes the results, your benchmark isn't fair.
    - https://stackoverflow.com/questions/6540386/assembly-performance-tuning
    - https://stackoverflow.com/questions/72282194/inline-assembly-array-sum-benchmark-near-zero-time-for-large-arrays-with-optimiz
- Reduce cache access times via core pinning
    - process: taskset
        ```sh
        taskset 1 foo
        # Validation
        taskset -p "$(pgrep foo)"
        ```
    - cgroups: cpuset
        - https://github.com/lpechacek/cpuset/blob/master/doc/tutorial.txt
    - systemd: cpu-affinity.conf
        ```sh
        mkdir -p /etc/systemd/system/foo.service.d
        printf '%s\n' '[Service]' 'CPUAffinity=0' > /etc/systemd/system/foo.service.d/cpu-affinity.conf
        ```
- Comparing compiler optimizations
    - https://stackoverflow.com/questions/32000917/c-loop-optimization-help-for-final-assignment-with-compiler-optimization-disabl/32001196#32001196
- [BenchmarkTools\.jl/linuxtips\.md at master · JuliaCI/BenchmarkTools\.jl · GitHub](https://github.com/JuliaCI/BenchmarkTools.jl/blob/master/docs/src/linuxtips.md)

# c

```c
static void DoSetup(const benchmark::State& state) {
}

static void DoTeardown(const benchmark::State& state) {
}

static void BM_func(benchmark::State& state) {...}

BENCHMARK(BM_func)->Arg(1)->Arg(3)->Threads(16)->Threads(32)->Setup(DoSetup)->Teardown(DoTeardown);

// Disabling optimizations

static void BM_vector_push_back(benchmark::State& state) {
  for (auto _ : state) {
    std::vector<int> v;
    v.reserve(1);
    benchmark::DoNotOptimize(v.data()); // Allow v.data() to be clobbered.
    v.push_back(42);
    benchmark::ClobberMemory(); // Force 42 to be written to memory.
  }
}

// Validating assembly

int ExternInt;
struct Point { int x, y, z; };

// CHECK-LABEL: test_store_point:
extern "C" void test_store_point() {
    Point p{ExternInt, ExternInt, ExternInt};
    benchmark::DoNotOptimize(p);

    // CHECK: movl ExternInt(%rip), %eax
    // CHECK: movl %eax, -{{[0-9]+}}(%rsp)
    // CHECK: movl %eax, -{{[0-9]+}}(%rsp)
    // CHECK: movl %eax, -{{[0-9]+}}(%rsp)
    // CHECK: ret
}
```

- https://github.com/google/benchmark/blob/main/docs/user_guide.md
- https://github.com/google/benchmark/blob/main/docs/AssemblyTests.md
- https://stackoverflow.com/questions/69287053/how-does-googles-donotoptimize-function-enforce-statement-ordering

# java

- https://www.oracle.com/technical-resources/articles/java/architect-benchmarking.html

# load testing

- http://highscalability.com/blog/2015/10/5/your-load-generator-is-probably-lying-to-you-take-the-red-pi.html
- [&quot;Benchmarking: You&\#39;re Doing It Wrong&quot; by Aysylu Greenberg \- YouTube](https://www.youtube.com/watch?v=XmImGiVuJno)
- [&quot;How NOT to Measure Latency&quot; by Gil Tene \- YouTube](https://www.youtube.com/watch?v=lJ8ydIuPFeU)
    - https://bravenewgeek.com/everything-you-know-about-latency-is-wrong/

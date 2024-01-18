# mysha

- My implementation of hashing algorithm SHA256 using rust, with animations of the process, to better understand how it works.

- Got the idea from [this youtube video](https:#www.youtube.com/watch?v=f9EbD6iY9zI&t=1194s&ab_channel=learnmeabitcoin), and decided to make my own implementation in rust.

# installation

- to install mysha you can compile it yourself if you have rust and cargo installed in your machine, by downloading the `rust-implementation` folder, and running the command inside the folder:
> `cargo install --path .`

- or you can download the compiled version for you OS on the releases tab.

- after the installation `mysha` should have a response on the terminal.


# manual

- This command line application hashes its input and prints it to the terminal, with additional options like animations.

> `mysha abc # should output ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad`

- it accepts multiple inputs(separated by space) to be hashed and different types of input([as described below](#t-type_input)).

> `mysha abc def ghi # hashes the three inputs passed`

- the inputs can be passed after the command or by the | operator.
- the input piped is devided by line and each line hashed.

> `cat hello.txt | mysha`

- and the output can be directed to a file with the > operator.

> `mysha hello > hello_hash.txt`


## Flags

### -a

- turns on the animations for the hashing process

> `mysha abc -a`

- Reccomendations:

    - for better experience, use the animation feature with the terminal in fullscreen and with the propper zoom out, so the entire content can fit the terminal.

    - use it with few and short(<=2 message schedules) messages. It should work with large and multiple messages, but I haven't optimized it for so. It is only for demonstration purposes.

### -e

- enables stepping through the animation by pressing enter, for a more slow and paused animation. Needs to have animation on for it to work, and the input needs to be stdin.

> `mysha abc -ae`


### -v

- prints more verbose output.

> `mysha abc -v`

### -t <TYPE>

- informs the program what type of input was passed, so it can be treated differently if necessary.

#### input type possible values:

- Text

    - default, it treats input as ASCII sequence.

    > `mysha abc -t text`

- Binary

    - treats the input as a binary data.

    > `mysha 1001001 -t binary`

- Hex

    - treats input as hexadecimal values.

    > `mysha abcff -t hex`

    - this is usefull for hashing data like bitcoin block headers or transactions, which need to be in hex mode and hashed twice(sha256(sha256(data))).

- decimal

    - treats input as a decimal number.

    > `mysha 73 -t decimal`

    - __obs__: it works with negative numbers, treating them as a 32 bit signed integer, however the command needs to be altered as not to treat the minus sign as a flag:
    > `mysha -t decimal -- -42`

- file

    - treats the input as files to be hashed, or path to the file.

    > `mysha hello.txt -t file`

    - this enables multiple files to be passed and hashed, with the command ls:

    > `ls -1 | mysha -t file # this should work on linux`

### -f

- makes the animation faster. by disabling some extra explanations. Animation must be enabled.

> `mysha abc -af`

### -s

- treats the input piped in(with the | operator) as one, doesn't separate by line.

> `cat hello.txt | mysha -s`

## -h or --help

- prints help information.

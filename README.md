# MySha

**MySha** is a cli tool with my implementation of different cryptography algorithms.

It is written in rust, and it consists of a binary crate, that is the cli tool itself, and a library crate, that enables using the cryptography algorithms and concepts in other code, and with more flexibility.

Below is the documentation on how to use mysha cli tool. For the documentation of the library, refer to [library doc](doc/mysha/index.html), since it is in HTML you may have to download it and open it with a browser.

<details>
<summary> Why "MySha"</summary>
<br>
The name MySha of the crate, and cli tool, it is because the cli tool was initially only my implementation of the sha256 algorithm, that is currently in the subcommand <a href="#sha256">sha256</a>, hence my implementation of sha algorithm, "mysha". However after that was completed I decided to add other cryptography tools and functionality to the same crate, and cli tool.
</details>
<br>

## installation

mysha isn't available on crates.io, as I decided not to upload it, so you can do either one of the following:

- Install it with this git repository, if you have rust and cargo installed in your machine, with this command:

    `cargo install --git https://github.com/lucasmabf/mysha`

- Download it and compile it yourself, if you have rust and cargo installed in your machine, by downloading the `MySha` crate folder, and running this command inside the folder:

    `cargo install --path .`

- Or download the compiled version for you OS on the [releases tab](https://github.com/lucasmabf/mysha/releases) and you would probably need to add it to your path variables as well.

After the installation `mysha` should have a response on the terminal.

## using the library

Since mysha isn't available on crates.io, you can't simply add it to your dependencies, you need to specify the git repository:

```toml
# Cargo.toml file
[dependencies]
mysha = {git = "https://github.com/lucasmabf/mysha}
```

Or you can also download the code, and add the dependency specifying the path to the crate on your computer:

```toml
# Cargo.toml file
[dependencies]
mysha = {path = "../mysha/mysha"} # change this to the path you downloaded the repository
```

## documentation

The mysha cli tool offers different cryptography commands, listed and explainded below.

For further instruction you can run the command:

`mysha help`, `mysha --help` or `mysha -h`

These commands also work for every subcommand, and provide information on the inputs that should be provided for every different command.

To see the tool's version, run:

`mysha --version` or `mysha -V`

### sha256

This subcommand hashes its input and prints it to the terminal, with additional options like animations.

`mysha sha256 abc # should output ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad`

My implementation of hashing algorithm SHA256 using rust, with animations of the process, to better understand how it works.

Got the idea from [this youtube video](https://www.youtube.com/watch?v=f9EbD6iY9zI&t=1194s&ab_channel=learnmeabitcoin), and decided to make my own implementation in rust.

It accepts multiple inputs(separated by space) to be hashed and different types of input.

`mysha sha256 abc def ghi # hashes the three inputs passed`

The inputs can be passed after the command or by the | operator. The input piped is devided by line and each line hashed.

`cat hello.txt | mysha sha256`

#### Flags

- --animation

    Turns on the animations for the hashing process

    `mysha sha256 abc -a`

    Reccomendations:

    - For better experience, use the animation feature with the terminal in fullscreen and with the propper zoom out, so the entire content can fit the terminal.

    - Use it with few and short(<=2 message schedules) messages. It should work with large and multiple messages, but I haven't optimized it for so. It is only for demonstration and learning purposes.

- --enter

    Enables stepping through the animation by pressing enter, for a more slow and paused animation. Needs to have animation on for it to work, and the input needs to be stdin.

    `mysha sha256 abc -ae`

- --verbose

    Prints more verbose output.

    `mysha sha256 abc -v`

- --type \<TYPE\>

    Informs the program what type of input was passed, so it can be treated differently if necessary.

    Input type possible values:

    - Text

        Default, it treats input text bytes, unicode if the terminal supports it, and ASCII if not.

        `mysha sha256 abc -t text`

    - Binary

        Treats the input as a binary data.

        `mysha sha256 1001001 -t binary`

    - Little endian binary value

        Treats the input as little endian binary data.

        `mysha sha256 1111111100000000 -t le-binary # same as hashing 0000000011111111`

    - Hex

        Treats input as hexadecimal values.

        `mysha sha256 abcff -t hex`

        This is usefull for hashing data like bitcoin block headers or transactions, which need to be in hex mode and hashed twice(sha256(sha256(data))).

    - Little endian hex

        Treats input as little endian hex values.

        `mysha sha256 abcd -t le-hex # same as hashing cdab`

    - Decimal

        Treats input as a decimal number.

        `mysha sha256 73 -t decimal`

        __obs__: It works with negative numbers, treating them as a 128 bit signed integer as complement, however the command needs to be altered as not to treat the minus sign as a flag:

        `mysha sha256 -t decimal -- -42`

    - File

        Treats the input as files to be hashed, or path to the file.

        `mysha sha256 hello.txt -t file`

        This enables multiple files to be passed and hashed, with the command ls:

        `ls -1 | mysha sha256 -t file # this should work on linux`

- --faster

    Makes the animation faster. by disabling some extra explanations. Animation must be enabled.

    `mysha sha256 abc -af`

- --separate-off

    Treats the input piped in(with the | operator) as one, doesn't separate by line.

    `cat hello.txt | mysha sha256 -s`

- --little-endian

    Displays output as little endian

    > `mysha hash256 abc # ad1500f261ff10b49c7a1796a36103b02322ae5dde404141eacf018fbf1678ba`

### ecc

The **ecc** subcommand is a tool that provides different elliptic curve and ECDSA functionality.

It can be used to do public key cryptography operations, such as creating key-pairs and signing messages.

This command generates output in toml format into a file, when `-o` is specified, so that the output 
can be stored and used later with other subcommands. The toml file has all parameters of ecc objects
and a specific format, that can be generated for given data with the subcommand `new`.

#### Subcommands

- generate \<PRIVATE\>

    Generates a new key pair from a provided number to serve as a private key, or generates a random one.

    To generate a key pair from a given private key just enter the private key.

    `mysha ecc generate 12 # not a very good private key`

    To generate a random private key type `random`.    

    `mysha ecc generate random`

    You can also leave it blank and it will also work:

    `mysha ecc generate`

    __Warning__: It doesn't use a CSPRNG(cryptographically secure pseudo random number generator), 
    so it is not reccomended for production, it is for demonstration purposes only.

    - Flags

        - --hex
        
            Treats input number \<PRIVATE\> as a hexadecimal number.

        - --little-endian

            Treats input number \<PRIVATE\> as little endian, needs to have hex enabled.

- sign \<MESSAGE\> --private \<PRIVATE\>

    Signs a message with the provided private key.

    The \<PRIVATE\> input is the private key file or the key pair file that will be used to sign the message.

    `mysha ecc --output signature sign --private keypair "Hello, World!"`
    - Flags:

        - --type

        Informs what type of data the message is, so it can be signed.

        It is the same type options as the hashing types explained above in the flags of the [sha256 subcommand](#sha256).

        `mysha ecc sign --private keypair 1001001 -t binary`    

- Verify \<SIGNATURE\> --message \<MESSAGE\>

    Verifies if the signature provided is valid for the given message.

    \<SIGNATURE\> is the toml signature file that will be validated.

    `mysha ecc verify signature -m "Hello, World!"`
    - Flags:

        - --type

        Informs what type of data the message is, so it can be signed.


        It is the same as the hashing types explained above in the flags of the [sha256 subcommand](#sha256).

- new

    Generates different objects in the toml output format that is used by the tool, for given values. So it can be written in a file 
    and used later as input.

    Options:

    - curve:

        Generates a curve from provided curve values or default, which is [secp256k1](https://www.secg.org/sec2-v2.pdf#Recommended%20Parameters%20secp256k1).

        - Flags:

            - -a \<A\>
        
                The _a_ parameter of the elliptic curve

            - -b \<B\>

                The _b parameter_ of the elliptic curve

            - -p \<P\>

                The modulo _p_ of the elliptic curve

            - -n \<N\>

                The order _n_  of the elliptic curve

            - -x \<X\>

                The _x coordinate_ of the _generator point_

            - -y \<Y\>

                The _y coordinate_ of the _generator point_

            - --hex

                Treats inputs from the other flags as hexadecimal numbers.

            - --little-endian

                Treats inputs from other flags as little endian, needs to have hex enabled.

        `mysha ecc --output curve_file new curve -a 2 -b 3 -p 97 -n 5 -x 3 -y 6 `

    - key-pair

        Generates a key pair from provided private key and public key.

        - Flags:

            - --private \<PRIVATE\>

                The _private key_

            - -x \<X\>

                The _x coordinate_ of the public key

            - -y \<Y\>

                The _y coordinate_ of the public key

            - --hex

                Treats inputs from the other flags as hexadecimal numbers.

            - --little-endian

                Treats inputs from other flags as little endian, needs to have hex enabled.
    
    - pub-key

        generates a public key from its coordinates.

        - Flags:

            - -x \<X\>

                The _x coordinate_ of the public key.

            - -y \<Y\>

                The _y coordinate_ of the public key.

            - --hex

                Treats inputs from the other flags as hexadecimal numbers.

            - --little-endian

                Treats inputs from other flags as little endian, needs to have hex enabled.
    
    - priv-key \<PRIVATE\>

        generates a toml private key.

        \<PRIVATE\> is the private key

        - Flags:

            - --hex

                Treats \<PRIVATE\> input as hexadecimal numbers.

            - --little-endian

                Treats \<PRIVATE\> input as little endian, needs to have hex enabled.

    - signature

        generates a toml signature from its values

        - Flags:

            - -x \<X\>

                The _x coordinate_ of the public key of the signer.

            - -y \<Y\>

                The _y coordinate_ of the public key of the signer.

            - -r \<R\>

                The _r part_ of the signature.

            - -s \<S\>

                The _s part_ of the signature.

            - --hex

                Treats inputs from the other flags as hexadecimal numbers.

            - --little-endian

                Treats inputs from other flags as little endian, needs to have hex enabled.

#### Flags

- --output \<OUTPUT-FILE\>

    Specifies file in which the toml output will be written. The output file, will contain ecc objects, 
    that can be used later on other commands.

    `mysha ecc -o keypair generate 1001001`

- --overwrite

    Turns off the safety error when trying to overwrite files with private keys.

    `mysha ecc --output private --overwrite generate`

- --curve \<CURVE-FILE>

    Changes the curve being used for operations to the curve specified in the given file.

    `mysha ecc -c curve_file generate 2`

- --hex

    Displays output as hexadecimal values.

- --little-endian

    Displays output in little endian. Needs to have hex enabled.

# Revealer
Revealer is an automated hybrid analysis tool for the detection of ReDoS vulnerabilities. For a given regex, it tries to find vulnerable patterns statically and generate a valid exploit dynamically.

Revealer is implemented based on the regex engine in the JDK 1.8 library.

You can find more information in the paper [Revealer: Detecting and Exploiting Regular Expression Denial-of-Service Vulnerabilities](https://www.computer.org/csdl/proceedings-article/sp/2021/893400b063/1t0x8WDjGGk). 

```tex
@INPROCEEDINGS {liu2021revealer,
    title = {Revealer: Detecting and Exploiting Regular Expression Denial-of-Service Vulnerabilities},
    author = {Liu, Yinxi and Zhang, Mingxue and Meng, Wei},
    booktitle = {2021 IEEE Symposium on Security and Privacy (SP)},
    pages = {1063-1079},
    year = {2021},
    issn = {2375-1207},
    doi = {10.1109/SP40001.2021.00062},
    url = {https://doi.ieeecomputersociety.org/10.1109/SP40001.2021.00062},
    publisher = {IEEE Computer Society}
}
```

## Quick start

### Build the project

Revealer manages its dependencies through maven, so you need to have JDK (1.8) and Maven installed, then run 
```
mvn clean package
```

A fat jar file containing all the project's dependencies is then located at `./target/Revealer-0.0.1-jar-with-dependencies`.

### Usage

This project contains three types of usage:

#### 1. Test single regex
Revealer tests the single regex if you send the regex as the single command-line argument.

For example, if you run:
```
java -jar target/Revealer-0.0.1-jar-with-dependencies.jar "/\\?\\w.*?\\[\\w.*?\[\\w.*?\\]\\]=/smiU"
```
you will get:
```
/\?\w.*?\[\w.*?\[\w.*?\]\]=/smiU
Find vulnerability (Polynomial) in structure!
{"regex":"/\\?\\w.*?\\[\\w.*?\\[\\w.*?\\]\\]=/smiU","prefix":"/?0[0","pump":"[0","suffix":"\n"}
```
Here the first line is the vulnerable regex, the second line is the vulnerability type, and the third line is the corresponding attack string information.

If the input regex is not vulnerable, you will see:
```
Contains no vulnerablity
```
Note that the input regex needs to be escaped! In this example, the backslash in the original regex `/\?\w.*?\[\w.*?\[\w.*?\]\]=/smiU` needs to be escaped by adding another backslash `"/\\?\\w.*?\\[\\w.*?\[\\w.*?\\]\\]=/smiU"`.

#### 2. Test regexes from datasets
This option runs by default (with no command-line argument). You need to create a `data` directory and put your dataset in it. The results will be saved in the `result` directory.
```
Revealer
├─src
├─target	# Revealer-0.0.1-jar-with-dependencies.jar
├─data	# put your dataset here!
│   ├─test1.txt
│   └─test2.txt
└─result # the results will show here!
    ├─vul-test1.txt
    └─vul-test2.txt
```
Then simply run:
```
java -jar target/Revealer-0.0.1-jar-with-dependencies.jar
```
Revealer would print the current regex to the command line interface. It would print a "finished" after processing of all regexes.

In the result file, for each vulnerable regex, similar to the single regex testing, Revealer outputs its vulnerability type and attack string information. There would be no information for those regexes with no vulnerabilities.

Note that using this option, you do not need to escape the regexes since they are read as raw lines.

#### 3. Validate attack string information
The third option allows you to provide two command-line arguments: {path-to-input-file} and {path-to-output-file}. It calculates the matching step using the attack string information with a maximum length of `128`. (The maximum matching step is set as `1e8` as in the paper.)

Each line of the input file should be a JSON object containing the regex, prefix, pump, and suffix fields.
You can take the `./attackInfo450.txt` as an example, it contains the `450` vulnerabilities that we detected using Revealer.  
```
java -jar target/Revealer-0.0.1-jar-with-dependencies.jar attackInfo450.txt out.txt 
```
For each line in the input file, Revealer prints the regex, a JSON object containing the regex and the attack string, and the matching step to the command line interface, e.g.,
```
(\w+[\.\_\-]*)*\w+@[\w]+(.)*\w+$
{"input":"0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000\b","pattern":"(\\w+[\\.\\_\\-]*)*\\w+@[\\w]+(.)*\\w+$"}
100000256
```
If the matching step is greater than `1e5`, the corresponding regex will appear in the output file.

## Copyright Information
Copyright © 2021 The Chinese University of Hong Kong

### Additional Notes

Notice that some files in Revealer may carry their own copyright notices.
In particular, Revealer's code release contains modifications to source files of the regex engine in the JDK 1.8 library and source files of the project [ReScue](https://github.com/2bdenny/ReScue).

## License
Check the LICENSE.md file.

## Contact ##
Yinxi Liu <yxliu@cse.cuhk.edu.hk>

[Mingxue Zhang](https://zhangmx1997.github.io/) <mxzhang@cse.cuhk.edu.hk>

[Wei Meng](https://www.cse.cuhk.edu.hk/~wei/) <wei@cse.cuhk.edu.hk>

[![penterepTools](https://www.penterep.com/external/penterepToolsLogo.png)](https://www.penterep.com/)


## ptvulns - Wrapper for testssl.sh


## Installation

```
pip install ptvulns
```

## Adding to PATH
If you're unable to invoke the script from your terminal, it's likely because it's not included in your PATH. You can resolve this issue by executing the following commands, depending on the shell you're using:

For Bash Users
```bash
echo "export PATH=\"`python3 -m site --user-base`/bin:\$PATH\"" >> ~/.bashrc
source ~/.bashrc
```

For ZSH Users
```bash
echo "export PATH=\"`python3 -m site --user-base`/bin:\$PATH\"" >> ~/.zshrc
source ~/.zshrc
```

## Usage examples
```
ptvulns -s "Apache 2.3"
ptvulns -s cpe:2.3:a:apache:camel:2.3.0:*:*:*:*:*:*:*
```

## Options
```
-s   --search           <search>  Search string for vulns
-vv  --verbose                    Show verbose output
-U   --update                     Update CPE db
-wd  --without-details            Show CVE without additional requests
-gv  --group-vulns                Group vulnerabilities for JSON
-v   --version                    Show script version and exit
-h   --help                       Show this help message and exit
-j   --json                       Output in JSON format
```

## Dependencies
```
ptlibs
```

## License

Copyright (c) 2025 Penterep Security s.r.o.

ptvulns is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

ptvulns is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with ptvulns. If not, see https://www.gnu.org/licenses/.

## Warning

You are only allowed to run the tool against the websites which
you have been given permission to pentest. We do not accept any
responsibility for any damage/harm that this application causes to your
computer, or your network. Penterep is not responsible for any illegal
or malicious use of this code. Be Ethical!
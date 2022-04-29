# HTTP Cats Splunk SOAR (Phantom) Application

*Work in progress..*

***Disclaimer**: The reversing of the product could be recognized as a breach of a license agreement and you should always consult with the vendor before decompiling binary files back into source code. Under no circumstances will I be held responsible or liable in any way for any claims, damages, losses, expenses, costs or liabilities whatsoever (including, without limitation, any direct or indirect damages for loss of profits, business interruption or loss of information) resulting or arising directly or indirectly from your use of or inability to use materials provided in this repository. You are responsible for your own
actions.*

HTTP Cats in a Splunk SOAR (Phantom) application meant for a demo integration purpose. The application currently covers the following topics:

- Downloading binary files;
- Placing files into Vault;
- Using custom widget to represent data;
- Showing file from Vault within the application's widget;

The application itself translates an HTTP response code into a visual representation using cat pictures from [https://http.cat](https://http.cat)

## Preparation

All Python code within the Splunk Phantom instances are compiled to binary files. Therefore, an IDE cannot provide code completion and proper syntax highlighting. However, the following steps can be used to prepare the code for the IDE:


```bash
pip install uncompyle6
decompiled_packages=~/.phantom-packages

mkdir -p $decompiled_packages

libs=( /opt/phantom/lib3/ /opt/phantom/pycommon3/ );
for lib_path in "${libs[@]}"; do cd $lib_path; \
  for file in $(find . -name "*.pyc"); do uncompyle6 -o $decompiled_packages/${file::-1} $file; done; \
done

# or

make prepare
```

## Development

Splunk Phantom (SOAR) application development could be done using a [community SOAR image](https://docs.splunk.com/Documentation/Phantom/4.10.7/Install/InstallOVA). Visual Studio Code has a capability to [use a remote server for development](https://code.visualstudio.com/docs/remote/ssh). Additionally, such setup supports most of the addons, such as [Pylance](https://github.com/microsoft/pylance-release). This gives a possibility to shorten the testing cycles and improve developer's morale. Because of that, most of the settings are tuned to be used within SOAR instance under user `phantom`.

[`Makefile`](./Makefile) contains some useful commands to automate some of the development tasks

```bash
# prepare local environment
make prepare

# install application in Splunk SOAR
make install

# access application execution failure logs
make logs
```


## Fix SSH Connectivity Timeout Issue

```bash
# /etc/ssh/sshd_config

RSAAuthentication yes
PubkeyAuthentication yes

GSSAPIAuthentication no

ClientAliveInterval 0
ClientAliveCountMax 3

UseDNS no

# Banner /etc/issue.net
```

## References

- [Install Splunk Phantom as a virtual machine image](https://docs.splunk.com/Documentation/Phantom/4.10.7/Install/InstallOVA)
- [Tutorial: Use the app wizard to develop an app framework](https://docs.splunk.com/Documentation/Phantom/4.10.7/DevelopApps/Tutorial)
- [Tutorial: Use the Splunk SOAR (Cloud) app wizard to develop an app framework](https://docs.splunk.com/Documentation/SOAR/current/DevelopApps/Tutorial)
- [A comprehensive guide to fixing slow SSH logins](https://jrs-s.net/2017/07/01/slow-ssh-logins/)
- [VSCode Python settings reference](https://code.visualstudio.com/docs/python/settings-reference)
- [SOAR Connector module development](https://docs.splunk.com/Documentation/Phantom/4.10.7/DevelopApps/Connector)
- [Vault usage example - splunk-soar-connectors/endace](https://github.com/splunk-soar-connectors/endace)

sudo apt update -y 
sudo apt install openjdk-11-jdk
sudo update-alternatives --config java
java --version

export PATH="/usr/lib/jvm/java-11-openjdk-amd64/bin:$PATH"

https://github.com/frohoff/ysoserial/issues/203

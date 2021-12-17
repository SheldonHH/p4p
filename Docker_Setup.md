# VSCode连接远程服务器里的docker容器
Source: https://zhuanlan.zhihu.com/p/361934730
[doubleZ](https://www.zhihu.com/people/doubleZ0108)

北京大学信息工程学院硕士在读

关注他

18 人赞同了该文章

以下以`testimage`镜像作为例子

## 在服务器容器中配置ssh

1. 通过一个其他的端口进入容器，这里使用6789端口

```bash
sudo docker run -it -d -p 5920:22 p4p:v1
```

2. 下载openssh

```bash
apt-get update
apt-get install openssh-server
```

3. 设置root密码

```bash
passwd
```

4. 然后设置两遍相同的密码，之后登陆的时候要用到！ 4. 修改配置文件

```bash
vim /etc/ssh/sshd_config
```

5. 注释掉 `PermitRootLogin prohibit-password` 这一行 添加这一行 `PermitRootLogin yes`5. 重启ssh服务

```bash
service ssh restart
# 或使用
# /etc/init.d/ssh restart
```

6. 本机连接ssh

```bash
ssh -p 6789 root@0.0.0.0
```

7. 远程访问服务器docker里正在运行的容器

```bash
ssh -p 6789 root@192.168.x.xx
```

【**报错**：ssh: connect to host 0.0.0.0 port 6789: Connection refused】

**原因**：没有开放对应端口

**解决方案**：在主机上

```text
sudo iptables -I INPUT -p tcp --dport 6789 -j ACCEPT
```

## 在自己电脑上配置vscode

1. 本地安装openssh，我用的是mac

```bash
brew install openssh
```

2. vscode中下载Remote-SSH插件

![img](https://pic4.zhimg.com/80/v2-fdfe4989f3f90199089f9b5b9967e40f_720w.jpg)

3. 使用插件连接远程服务器里的容器

![img](https://pic3.zhimg.com/80/v2-8c24b535b938337c7ad6e1744cbe92d2_720w.jpg)



> 注：之前一直用的是Remote-Container，以为可以更方便的连接到服务器里的docker，屡次尝试都不成功，查了些其他人的博客说Remote-Container只能连接本地自己电脑里的docker emmmm…

## Resources

- [Docker Ubuntu上安装ssh和连接ssh_JustToFaith-CSDN博客](https://link.zhihu.com/?target=https%3A//blog.csdn.net/qq_43914736/article/details/90608587)
- [VSCode+Docker: 打造最舒适的深度学习环境 - 知乎](https://zhuanlan.zhihu.com/p/80099904)
- [VSCode中利用Remote SSH插件远程连接服务器并进行远程开发_lenfranky的博客-CSDN博客](https://link.zhihu.com/?target=https%3A//blog.csdn.net/lenfranky/article/details/89972889)
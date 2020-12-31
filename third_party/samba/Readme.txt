1. python版本需要支持-fpic编译结果；
../configure --prefix=/usr/local --enable-shared
./configure --prefix=/usr/local/python38 --enable-shared

2、guntls需要3.4.9版本以上

./configure --with-included-libtasn1 --with-included-unistring --without-p11-kit
./configure --bindir=/usr/bin/   --sbindir=/usr/sbin/    --libexecdir=/usr/libexec/             --sysconfdir=/etc/             --libdir=/usr/lib64/             --includedir=/usr/include/             --datarootdir=/usr/share/   --infodir=/usr/share/info/    --localedir=/usr/share/locale/     --mandir=/usr/share/man/     --docdir=/usr/share/doc/gnutls/    --disable-guile    --without-p11-kit
安装指导
https://www.cmdschool.org/archives/6646
https://blog.csdn.net/qq123456q1/article/details/91410183

3. nettle
 guntls 依赖

4.编译器需要7以上
yum install -y devtoolset-8-toolchain
scl enable devtoolset-8 bash

5.依赖库
https://wiki.samba.org/index.php/Package_Dependencies_Required_to_Build_Samba

CENTOS
yum install docbook-style-xsl gcc gdb gnutls-devel gpgme-devel jansson-devel \
      keyutils-libs-devel krb5-workstation libacl-devel libaio-devel \
      libarchive-devel libattr-devel libblkid-devel libtasn1 libtasn1-tools \
      libxml2-devel libxslt lmdb-devel openldap-devel pam-devel perl \
      perl-ExtUtils-MakeMaker perl-Parse-Yapp popt-devel python3-cryptography \
      python3-dns python3-gpg python36-devel readline-devel rpcgen systemd-devel \
      tar zlib-devel

6、出现tmp read open失败，
则编译选项增加-pipe
./configure --prefix=/usr/local/samba CFLAGS+='-pipe' --enable-cafs
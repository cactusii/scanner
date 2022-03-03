资产扫描工具——用以发现IP、服务、站点、子域名等资产，支持带权限的扫描和添加指纹功能。

## Usage

```bash
# python 3.6
apt install gcc docker-compose nginx-core docker.io nmap -y
pip install -r requirement.txt
script/docker-compose up -d
```

### database
```bash
mysql -h 127.0.0.1 -uroot -p123123 -s <<EOT
create database if not exists property_db default charset utf8 collate utf8_general_ci;
QUIT
EOT
```

### deploy web locally
```bash
python3 manage.py makemigrations --empty api
python3 manage.py makemigrations
python3 manage.py migrate
python3 manage.py runserver
```


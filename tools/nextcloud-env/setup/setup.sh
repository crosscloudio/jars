
# wait for mysql
# mysqli version

MYSQL_HOST=nextcloud-db
MYSQL_DB=nextcloud
MYSQL_USER=nextcloud
MYSQL_PASSWORD=supersecretpassword
# until php -r "mysqli_connect('nextcloud-db', 'nextcloud', 'supersecretpassword') or exit(-1);"; do
until php -r "new PDO('mysql:host=${MYSQL_HOST};dbname=${MYSQL_DB}', '${MYSQL_USER}','${MYSQL_PASSWORD}');"; do
  echo "Mysql is unavailable - sleeping"
  sleep 1
done

echo "Mysql available - starting"


su -s /bin/sh www-data -c "php occ maintenance:install \
 --admin-user=testuser \
 --admin-pass=testpass \
 --database=mysql \
 --database-name=${MYSQL_DB} \
 --database-host=${MYSQL_HOST} \
 --database-user=${MYSQL_USER} \
 --database-pass=${MYSQL_PASSWORD}"

# add nextcloud/owncloud as trusted domain
su -s /bin/sh www-data -c "php occ config:system:set trusted_domains 1 --value=nextcloud"
su -s /bin/sh www-data -c "php occ config:system:set trusted_domains 2 --value=owncloud"

# start it
apache2-foreground

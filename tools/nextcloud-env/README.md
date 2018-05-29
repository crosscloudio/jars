Using of the docker-compose scripts to test the owncloud/nextcloud implementations.

```
CLOUD_IMAGE=owncloud:10 docker-compose up
```

will startup a docker for mariadb and owncloud:10.

To stop everything call:
```
docker-compose stop
```

To get rid of the data, call
```
docker-compose rm -f
```

## Using it in the storage tests

The storage tests are defaulting to http://nextcloud/, so please adjust your hosts to make it work.
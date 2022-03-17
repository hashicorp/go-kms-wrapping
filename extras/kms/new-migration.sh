#! /bin/sh
migrate create -ext sql -dir migrations/$1 -tz utc $2